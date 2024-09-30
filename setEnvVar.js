const { resolve, join } = require('path');
const { homedir } = require('os');
const { readFileSync, writeFileSync, existsSync } = require('fs');
const readline = require('readline');

function setEnvVar(key, value) {
    const envFilePath = resolve(join(homedir(), '.openkbs', '.env'));

    let envFileContent = '';
    if (existsSync(envFilePath)) {
        envFileContent = readFileSync(envFilePath, 'utf-8');
    }

    const envVariables = envFileContent.split('\n').filter(line => line.trim() !== '');
    const existingVarIndex = envVariables.findIndex(line => line.startsWith(`${key}=`));

    if (existingVarIndex !== -1) {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        rl.question(`The key "${key}" already exists. Do you want to override it? (yes/no): `, (answer) => {
            if (answer.toLowerCase() === 'yes') {
                envVariables[existingVarIndex] = `${key}=${value}`;
                writeFileSync(envFilePath, envVariables.join('\n'), 'utf-8');
                console.log(`The key "${key}" has been updated.`);
            } else {
                console.log(`The key "${key}" was not updated.`);
            }
            rl.close();
        });
    } else {
        envVariables.push(`${key}=${value}`);
        writeFileSync(envFilePath, envVariables.join('\n'), 'utf-8');
        console.log(`The key "${key}" has been added.`);
    }
}

const [,, key, value] = process.argv;
if (key && value) {
    setEnvVar(key, value);
} else {
    console.error('Usage: node setEnvVar.js <key> <value>');
}