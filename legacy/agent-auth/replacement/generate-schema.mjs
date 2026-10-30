import {DatabaseSync} from 'node:sqlite';
import {getMigrations} from 'better-auth/db/migration';
import {writeFile,readFile} from 'node:fs/promises';
import {authOptions} from './config.mjs';
const database=new DatabaseSync(':memory:');
const plan=await getMigrations(authOptions({database,secret:'schema-generation-local-only-no-server-identity'}));
if(plan.unsafeChanges.length || plan.schemaProblems.length) throw Error('schema_generation_rejected');
const sql=await plan.compileMigrations();
const target=new URL('./schema.sql',import.meta.url);
const expected='-- Generated from Better Auth 1.7.14 / Agent Auth 0.6.2. Additive NEW database only.\n'+sql;
if(process.argv.includes('--check')){if(await readFile(target,'utf8')!==expected)throw Error('schema_snapshot_drift');}
else await writeFile(target,expected);
database.close();
