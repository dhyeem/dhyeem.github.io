import { readFileSync, writeFileSync } from 'node:fs';
import { stripSecrets } from '../js/parsers/config.js';
const raw = readFileSync(new URL('../Working DMM_VG.txt', import.meta.url), 'utf8');
writeFileSync(new URL('../samples/running-config.txt', import.meta.url), stripSecrets(raw));

