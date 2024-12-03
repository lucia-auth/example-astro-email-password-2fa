export class TokenBucketRateLimit<_Key> {
	public max: number;
	public refillIntervalSeconds: number;

	constructor(max: number, refillIntervalSeconds: number) {
		this.max = max;
		this.refillIntervalSeconds = refillIntervalSeconds;
	}

	private storage = new Map<_Key, RefillingTokenBucket>();

	public check(key: _Key, cost: number): boolean {
		const bucket = this.storage.get(key) ?? null;
		if (bucket === null) {
			return true;
		}
		const now = Date.now();
		const refill = Math.floor((now - bucket.refilledAt) / (this.refillIntervalSeconds * 1000));
		const count = Math.min(bucket.count + refill, this.max);
		return count >= cost;
	}

	public consume(key: _Key, cost: number): boolean {
		let bucket = this.storage.get(key) ?? null;
		const now = Date.now();
		if (bucket === null) {
			bucket = {
				count: this.max - cost,
				refilledAt: now
			};
			this.storage.set(key, bucket);
			return true;
		}
		const refill = Math.floor((now - bucket.refilledAt) / (this.refillIntervalSeconds * 1000));
		bucket.count = Math.min(bucket.count + refill, this.max);
		bucket.refilledAt = bucket.refilledAt + refill * this.refillIntervalSeconds;
		if (bucket.count < cost) {
			return false;
		}
		bucket.count -= cost;
		this.storage.set(key, bucket);
		return true;
	}
}

export class BasicRateLimit<_Key> {
	public max: number;
	public windowSizeInSeconds: number;

	private storage = new Map<_Key, BasicRateLimitRecord>();

	constructor(max: number, windowSizeInSeconds: number) {
		this.max = max;
		this.windowSizeInSeconds = windowSizeInSeconds;
	}

	public check(key: _Key, cost: number): boolean {
		const record = this.storage.get(key) ?? null;
		if (record === null) {
			return true;
		}
		if (Date.now() - record.startsAt >= this.windowSizeInSeconds * 1000) {
			return true;
		}
		return record.count >= cost;
	}

	public consume(key: _Key, cost: number): boolean {
		let record = this.storage.get(key) ?? null;
		const now = Date.now();
		if (record === null) {
			record = {
				count: this.max - cost,
				startsAt: now
			};
			this.storage.set(key, record);
			return true;
		}
		if (now - record.startsAt >= this.windowSizeInSeconds * 1000) {
			record.count = this.max;
		}
		if (record.count < cost) {
			return false;
		}
		record.count -= cost;
		this.storage.set(key, record);
		return true;
	}

	public reset(key: _Key): void {
		this.storage.delete(key);
	}
}

export class Counter<_Key> {
	public max: number;

	private storage = new Map<_Key, number>();

	constructor(max: number) {
		this.max = max;
	}

	public increment(key: _Key): boolean {
		let count = this.storage.get(key) ?? 0;
		if (count > this.max) {
			this.storage.delete(key);
			return false;
		}
		count++;
		this.storage.set(key, count);
		return true;
	}
}

interface RefillingTokenBucket {
	count: number;
	refilledAt: number;
}

interface BasicRateLimitRecord {
	count: number;
	startsAt: number;
}
