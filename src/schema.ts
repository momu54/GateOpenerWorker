import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

export const publicKeysTable = sqliteTable('public_keys', {
	id: integer('id').primaryKey({
		autoIncrement: true,
	}),
	key: text('key').notNull(),
	trusted: integer('trusted').notNull().default(0),
});
