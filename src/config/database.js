import 'dotenv/config.js';

import {neon} from '@neondatabase/serverless';
import {drizzle} from 'drizzle-orm/neon-https';

const sql = neon(process.env.DB_URL);

const db = drizzle(sql);

export { db, sql };