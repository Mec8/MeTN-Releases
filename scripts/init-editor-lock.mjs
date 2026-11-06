import{pbkdf2Sync,randomBytes}from'node:crypto';import{writeFile}from'node:fs/promises';
process.stdout.write('Input editor password on stdin (not echoed):\n');
if(process.stdin.isTTY)process.stdin.setRawMode(true);
let input='';for await(const chunk of process.stdin){input+=chunk;if(input.includes('\n')||input.includes('\r'))break;}
if(process.stdin.isTTY)process.stdin.setRawMode(false);
const password=input.replace(/[\r\n]+$/,'');if(password.length<8)throw Error('Password must contain at least 8 characters');
const salt=randomBytes(16);const config={algorithm:'PBKDF2-SHA256',iterations:310000,salt:salt.toString('hex'),hash:pbkdf2Sync(password,salt,310000,32,'sha256').toString('hex')};
await writeFile(new URL('../dist/editor-lock.json',import.meta.url),JSON.stringify(config,null,2)+'\n');input='';console.log('Editor lock configured. This is not GitHub authorization.');
