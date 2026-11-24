import {cp, mkdir, rm} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
const source = new URL('./logban/', import.meta.url);
const target = new URL('../internal/webui/assets/', import.meta.url);
await rm(target, {recursive:true, force:true});
await mkdir(target, {recursive:true});
await cp(source, target, {recursive:true});
console.log('Built LogBan UI:', fileURLToPath(target));
