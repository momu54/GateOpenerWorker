import { and, eq, sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/d1';
import { publicKeysTable } from './schema';

enum DoorAction {
	OPEN = 'OPEN',
	STOP = 'STOP',
	CLOSE = 'CLOSE',
}

interface DoorRequestPayload {
	signature: string;
	action: DoorAction;
	publicKey: string;
}

interface KeyStore {
	key: string;
	trusted: boolean;
}

interface Env {
	PublicKeys: D1Database;
	ENVIRONMENT: string;
	GATE_HMAC_KEY: string;
	GATE_URL: string;
}

interface JsonResponseBody {
	status: 'success' | 'failed';
	message?: string;
}

interface ValueToGate {
	action: DoorAction;
	nonce: number;
	expiry: string;
}

interface PayloadToGate {
	value: ValueToGate;
	signature: string;
}

declare global {
	interface JSON {
		stringify<T>(value: T): string;
		parse<T>(text: string): T;
	}
}

function toInt(value: boolean) {
	return value ? 1 : 0;
}

function NewJsonResponse<OtherRecord = {}>(status: number, body: JsonResponseBody & OtherRecord) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

const GetMethodNotAllowedResponse = () => NewJsonResponse(405, { status: 'failed', message: 'Method Not Allowed' });
const GetUnauthorizedResponse = () => NewJsonResponse(401, { status: 'failed', message: 'Unauthorized' });

const PublicKeyPostHandler: ExportedHandlerFetchHandler<Env> = async (request, env, _ctx) => {
	const publicKeysDB = drizzle(env.PublicKeys, { schema: { public_keys: publicKeysTable } });
	const recivedKey = await request.text();
	const storedKey = await publicKeysDB.query.public_keys.findFirst({
		where: eq(publicKeysTable.key, recivedKey),
	});
	if (storedKey) return NewJsonResponse(409, { status: 'failed', message: 'Key already exists' });
	await publicKeysDB.insert(publicKeysTable).values({
		key: recivedKey,
		trusted: toInt(false),
	});
	return NewJsonResponse<{ key: string }>(200, { status: 'success', key: recivedKey, message: 'Key added' });
};

const PublicKeyGetHandler: ExportedHandlerFetchHandler<Env> = async (request, env, _ctx) => {
	const publicKeysDB = drizzle(env.PublicKeys, { schema: { public_keys: publicKeysTable } });
	const keys = await publicKeysDB.query.public_keys.findMany();
	if (keys.length === 0) return NewJsonResponse(404, { status: 'failed', message: 'No keys found' });

	return NewJsonResponse<{ keys: KeyStore[] }>(200, {
		status: 'success',
		keys: keys.map((key) => ({ key: key.key, trusted: !!key.trusted })),
	});
};

const PublicKeyDeleteHandler: ExportedHandlerFetchHandler<Env> = async (request, env, _ctx) => {
	const publicKeysDB = drizzle(env.PublicKeys, { schema: { public_keys: publicKeysTable } });
	const recivedKey = await request.text();
	const storedKey = await publicKeysDB.query.public_keys.findFirst({
		where: eq(publicKeysTable.key, recivedKey),
	});
	if (!storedKey) return NewJsonResponse(404, { status: 'failed', message: 'Key not found' });

	await publicKeysDB.delete(publicKeysTable).where(eq(publicKeysTable.key, recivedKey));
	return NewJsonResponse<{ key: string }>(200, { status: 'success', key: recivedKey, message: 'Key deleted' });
};

const PublicKeyUpdateHandler: ExportedHandlerFetchHandler<Env> = async (request, env, _ctx) => {
	const publicKeysDB = drizzle(env.PublicKeys, { schema: { public_keys: publicKeysTable } });
	const updateTo = await request.json<KeyStore>();
	await publicKeysDB
		.update(publicKeysTable)
		.set({
			trusted: toInt(updateTo.trusted),
			key: updateTo.key,
		})
		.where(eq(publicKeysTable.key, updateTo.key));
	return NewJsonResponse<{ newKey: KeyStore }>(200, { newKey: updateTo, status: 'success', message: 'Key updated' });
};

const TableHandler: ExportedHandlerFetchHandler<Env> = async (_request, env, _ctx) => {
	const publicKeysDB = drizzle(env.PublicKeys, { schema: { public_keys: publicKeysTable } });
	await publicKeysDB.run(sql`CREATE TABLE IF NOT EXISTS public_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT NOT NULL,
		trusted INTEGER NOT NULL DEFAULT 0
	)`);
	return NewJsonResponse(200, { status: 'success', message: 'Table created or already exists' });
};

async function SendToGate(action: DoorAction, env: Env) {
	const hmacKey = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(env.GATE_HMAC_KEY),
		{
			name: 'HMAC',
			hash: 'SHA-256',
		},
		false,
		['sign']
	);

	const encoder = new TextEncoder();
	const expiry = new Date();
	expiry.setMinutes(expiry.getMinutes() + 1);
	const value: ValueToGate = { action, expiry: expiry.toISOString(), nonce: Math.floor(Math.random() * 1000000000) };
	const signatureBinarys = await crypto.subtle.sign(
		{
			name: 'HMAC',
		},
		hmacKey,
		encoder.encode(JSON.stringify<ValueToGate>(value))
	);

	const payload: PayloadToGate = {
		value,
		signature: btoa(String.fromCharCode(...new Uint8Array(signatureBinarys))),
	};
	const response = await fetch(env.GATE_URL, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(payload),
	});

	return response.ok
		? NewJsonResponse(200, {
				status: 'success',
				message: `Gate action ${action} sent successfully`,
		  })
		: response;
}

const GateHandler: ExportedHandlerFetchHandler<Env> = async (request, env): Promise<Response> => {
	const publicKeysDB = drizzle(env.PublicKeys, { schema: { public_keys: publicKeysTable } });

	const requestPayload: DoorRequestPayload = await request.json();

	const key = await publicKeysDB.query.public_keys.findFirst({
		where: and(eq(publicKeysTable.trusted, toInt(true)), eq(publicKeysTable.key, requestPayload.publicKey)),
	});

	if (!key) return GetUnauthorizedResponse();

	const encoder = new TextEncoder();
	const recivedKeyBinary = encoder.encode(requestPayload.publicKey);
	const signatureBinary = encoder.encode(requestPayload.signature);
	const recivedKey = await crypto.subtle.importKey(
		'spki',
		recivedKeyBinary,
		{
			name: 'RSASSA-PKCS1-v1_5',
			hash: 'SHA-256',
		},
		false,
		['verify']
	);

	const VerifyResult = await crypto.subtle.verify(
		{
			name: 'RSASSA-PKCS1-v1_5',
			saltLength: 32,
		},
		recivedKey,
		signatureBinary,
		encoder.encode(requestPayload.action)
	);

	if (!VerifyResult) {
		return GetUnauthorizedResponse();
	}

	return await SendToGate(requestPayload.action, env);
};

const GetNotProductionResponse = () => NewJsonResponse(403, { status: 'failed', message: 'Not allowed in production' });

export default {
	async fetch(request, env, context) {
		const { pathname } = new URL(request.url);
		switch (pathname) {
			case '/publicKey':
				switch (request.method) {
					case 'POST':
						return await PublicKeyPostHandler(request, env, context);
					case 'GET':
						if (env.ENVIRONMENT !== 'DEVELOPMENT') return GetNotProductionResponse();
						return await PublicKeyGetHandler(request, env, context);
					case 'DELETE':
						if (env.ENVIRONMENT !== 'DEVELOPMENT') return GetNotProductionResponse();
						return await PublicKeyDeleteHandler(request, env, context);
					case 'PATCH':
						if (env.ENVIRONMENT !== 'DEVELOPMENT') return GetNotProductionResponse();
						return await PublicKeyUpdateHandler(request, env, context);
					default:
						return GetMethodNotAllowedResponse();
				}
			case '/table':
				if (env.ENVIRONMENT !== 'DEVELOPMENT') return GetNotProductionResponse();
				if (request.method !== 'PUT') return GetMethodNotAllowedResponse();
				return await TableHandler(request, env, context);
			case '/gate':
				if (request.method !== 'PATCH') return GetMethodNotAllowedResponse();
				return GateHandler(request, env, context);
		}

		return NewJsonResponse(404, { status: 'failed', message: 'Not Found' });
	},
} satisfies ExportedHandler<Env>;
