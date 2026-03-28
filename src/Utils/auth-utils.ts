import NodeCache from '@cacheable/node-cache'
import { AsyncLocalStorage } from 'async_hooks'
import { Mutex } from 'async-mutex'
import { randomBytes } from 'crypto'
import PQueue from 'p-queue'
import { DEFAULT_CACHE_TTLS } from '../Defaults'
import type {
	AuthenticationCreds,
	CacheStore,
	SignalDataSet,
	SignalDataTypeMap,
	SignalKeyStore,
	SignalKeyStoreWithTransaction,
	TransactionCapabilityOptions
} from '../Types'
import { Curve, signedKeyPair } from './crypto'
import { delay, generateRegistrationId } from './generics'
import type { ILogger } from './logger'
import { PreKeyManager } from './pre-key-manager'

interface TransactionContext {
	cache: SignalDataSet
	mutations: SignalDataSet
	dbQueries: number
	sessionId: string
}

// Multi session storage
const sessionCaches = new Map<string, CacheStore>()
const sessionKeyQueues = new Map<string, Map<string, PQueue>>()
const sessionTxMutexes = new Map<string, Map<string, Mutex>>()
const sessionTxMutexRefCounts = new Map<string, Map<string, number>>()

function getCacheForSession(sessionId: string, baseCache?: CacheStore): CacheStore {
	if (sessionCaches.has(sessionId)) {
		return sessionCaches.get(sessionId)!
	}
	const cache = baseCache || new NodeCache({
		stdTTL: DEFAULT_CACHE_TTLS.SIGNAL_STORE,
		useClones: false,
		deleteOnExpire: true
	}) as unknown as CacheStore
	sessionCaches.set(sessionId, cache)
	return cache
}

function getQueueForSession(sessionId: string, key: string): PQueue {
	if (!sessionKeyQueues.has(sessionId)) {
		sessionKeyQueues.set(sessionId, new Map())
	}
	const queues = sessionKeyQueues.get(sessionId)!
	if (!queues.has(key)) {
		queues.set(key, new PQueue({ concurrency: 1 }))
	}
	return queues.get(key)!
}

function getTxMutexForSession(sessionId: string, key: string): Mutex {
	if (!sessionTxMutexes.has(sessionId)) {
		sessionTxMutexes.set(sessionId, new Map())
		sessionTxMutexRefCounts.set(sessionId, new Map())
	}
	const mutexes = sessionTxMutexes.get(sessionId)!
	if (!mutexes.has(key)) {
		mutexes.set(key, new Mutex())
		const refCounts = sessionTxMutexRefCounts.get(sessionId)!
		refCounts.set(key, 0)
	}
	return mutexes.get(key)!
}

function acquireTxMutexRefForSession(sessionId: string, key: string): void {
	const refCounts = sessionTxMutexRefCounts.get(sessionId)
	if (!refCounts) return
	const count = refCounts.get(key) ?? 0
	refCounts.set(key, count + 1)
}

function releaseTxMutexRefForSession(sessionId: string, key: string): void {
	const refCounts = sessionTxMutexRefCounts.get(sessionId)
	if (!refCounts) return
	const count = (refCounts.get(key) ?? 1) - 1
	if (count <= 0) {
		refCounts.delete(key)
		const mutexes = sessionTxMutexes.get(sessionId)
		if (mutexes && mutexes.has(key) && !mutexes.get(key)!.isLocked()) {
			mutexes.delete(key)
		}
	} else {
		refCounts.set(key, count)
	}
	if (refCounts.size === 0) {
		sessionTxMutexRefCounts.delete(sessionId)
		sessionTxMutexes.delete(sessionId)
	}
	if (sessionKeyQueues.has(sessionId) && sessionKeyQueues.get(sessionId)!.size === 0) {
		sessionKeyQueues.delete(sessionId)
	}
	if (sessionCaches.has(sessionId) && !sessionTxMutexes.has(sessionId) && !sessionKeyQueues.has(sessionId)) {
		sessionCaches.delete(sessionId)
	}
}

export function makeCacheableSignalKeyStore(
	store: SignalKeyStore,
	logger?: ILogger,
	_cache?: CacheStore,
	sessionId: string = 'default'
): SignalKeyStore {
	const cache = getCacheForSession(sessionId, _cache)

	function getUniqueId(type: string, id: string) {
		return `${sessionId}.${type}.${id}`
	}

	return {
		async get(type, ids) {
			const data: { [_: string]: SignalDataTypeMap[typeof type] } = {}
			const idsToFetch: string[] = []

			for (const id of ids) {
				const item = (await cache.get<SignalDataTypeMap[typeof type]>(getUniqueId(type, id))) as any
				if (typeof item !== 'undefined') {
					data[id] = item
				} else {
					idsToFetch.push(id)
				}
			}

			if (idsToFetch.length) {
				logger?.trace({ items: idsToFetch.length, sessionId }, 'loading from store')
				const fetched = await store.get(type, idsToFetch)
				for (const id of idsToFetch) {
					const item = fetched[id]
					if (item) {
						data[id] = item
						await cache.set(getUniqueId(type, id), item as SignalDataTypeMap[keyof SignalDataTypeMap])
					}
				}
			}

			return data
		},
		async set(data) {
			let keys = 0
			for (const type in data) {
				for (const id in data[type as keyof SignalDataTypeMap]) {
					await cache.set(getUniqueId(type, id), data[type as keyof SignalDataTypeMap]![id]!)
					keys += 1
				}
			}
			logger?.trace({ keys, sessionId }, 'updated cache')
			await store.set(data)
		},
		async clear() {
			await cache.flushAll()
			await store.clear?.()
		}
	}
}

export const addTransactionCapability = (
	state: SignalKeyStore,
	logger: ILogger,
	{ maxCommitRetries, delayBetweenTriesMs }: TransactionCapabilityOptions,
	sessionId: string = 'default'
): SignalKeyStoreWithTransaction => {
	const txStorage = new AsyncLocalStorage<TransactionContext>()
	const preKeyManager = new PreKeyManager(state, logger)

	function isInTransaction(): boolean {
		return !!txStorage.getStore()
	}

	async function commitWithRetry(mutations: SignalDataSet): Promise<void> {
		if (Object.keys(mutations).length === 0) {
			logger.trace({ sessionId }, 'no mutations in transaction')
			return
		}
		logger.trace({ sessionId, mutationCount: Object.keys(mutations).length }, 'committing transaction')
		for (let attempt = 0; attempt < maxCommitRetries; attempt++) {
			try {
				await state.set(mutations)
				logger.trace({ sessionId }, 'committed transaction')
				return
			} catch (error) {
				const retriesLeft = maxCommitRetries - attempt - 1
				logger.warn({ sessionId, error, retriesLeft }, 'failed to commit mutations')
				if (retriesLeft === 0) throw error
				await delay(delayBetweenTriesMs)
			}
		}
	}

	return {
		get: async (type, ids) => {
			const ctx = txStorage.getStore()
			if (!ctx) return state.get(type, ids)

			const cached = ctx.cache[type] || {}
			const missing = ids.filter(id => !(id in cached))
			if (missing.length > 0) {
				ctx.dbQueries++
				logger.trace({ sessionId, type, count: missing.length }, 'fetching missing keys in transaction')
				const fetched = await getTxMutexForSession(sessionId, type).runExclusive(() => state.get(type, missing))
				ctx.cache[type] = ctx.cache[type] || ({} as any)
				Object.assign(ctx.cache[type]!, fetched)
			}
			const result: { [key: string]: any } = {}
			for (const id of ids) {
				const value = ctx.cache[type]?.[id]
				if (value !== undefined && value !== null) result[id] = value
			}
			return result
		},
		set: async data => {
			const ctx = txStorage.getStore()
			if (!ctx) {
				const types = Object.keys(data)
				for (const type_ of types) {
					const type = type_ as keyof SignalDataTypeMap
					if (type === 'pre-key') {
						await preKeyManager.validateDeletions(data, type)
					}
				}
				await Promise.all(
					types.map(type =>
						getQueueForSession(sessionId, type).add(async () => {
							const typeData = { [type]: data[type as keyof SignalDataTypeMap] } as SignalDataSet
							await state.set(typeData)
						})
					)
				)
				return
			}
			logger.trace({ sessionId, types: Object.keys(data) }, 'caching in transaction')
			for (const key_ in data) {
				const key = key_ as keyof SignalDataTypeMap
				ctx.cache[key] = ctx.cache[key] || ({} as any)
				ctx.mutations[key] = ctx.mutations[key] || ({} as any)
				if (key === 'pre-key') {
					await preKeyManager.processOperations(data, key, ctx.cache, ctx.mutations, true)
				} else {
					Object.assign(ctx.cache[key]!, data[key])
					Object.assign(ctx.mutations[key]!, data[key])
				}
			}
		},
		isInTransaction,
		transaction: async (work, key) => {
			const existing = txStorage.getStore()
			if (existing) {
				logger.trace({ sessionId }, 'reusing existing transaction context')
				return work()
			}
			const mutex = getTxMutexForSession(sessionId, key)
			acquireTxMutexRefForSession(sessionId, key)
			try {
				return await mutex.runExclusive(async () => {
					const ctx: TransactionContext = { cache: {}, mutations: {}, dbQueries: 0, sessionId }
					logger.trace({ sessionId }, 'entering transaction')
					try {
						const result = await txStorage.run(ctx, work)
						await commitWithRetry(ctx.mutations)
						logger.trace({ sessionId, dbQueries: ctx.dbQueries }, 'transaction completed')
						return result
					} catch (error) {
						logger.error({ sessionId, error }, 'transaction failed, rolling back')
						throw error
					}
				})
			} finally {
				releaseTxMutexRefForSession(sessionId, key)
			}
		}
	}
}

export const initAuthCreds = (): AuthenticationCreds => {
	const identityKey = Curve.generateKeyPair()
	return {
		noiseKey: Curve.generateKeyPair(),
		pairingEphemeralKeyPair: Curve.generateKeyPair(),
		signedIdentityKey: identityKey,
		signedPreKey: signedKeyPair(identityKey, 1),
		registrationId: generateRegistrationId(),
		advSecretKey: randomBytes(32).toString('base64'),
		processedHistoryMessages: [],
		nextPreKeyId: 1,
		firstUnuploadedPreKeyId: 1,
		accountSyncCounter: 0,
		accountSettings: {
			unarchiveChats: false
		},
		registered: false,
		pairingCode: undefined,
		lastPropHash: undefined,
		routingInfo: undefined,
		additionalData: undefined
	}
		}
