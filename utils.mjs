import AWS from "aws-sdk";
import jwt from "jsonwebtoken";
import CryptoJS from "crypto-js";
import NodeRSA from "node-rsa";
import {promisify} from 'util';
import crypto from 'crypto';
import {defaultProvider} from "@aws-sdk/credential-provider-node";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import https from 'https';
import http from 'http';
import axios from 'axios';
import express from "express";
import { readFileSync } from 'fs';
import { resolve, join } from 'path';
import { homedir } from 'os';
import bs58 from 'bs58';
import url from 'url';
import WebSocket, { WebSocketServer } from 'ws';
import { promises as fs } from 'fs';
import readline from 'readline';

const s3Client = new S3Client({
    region: 'us-east-1',
    endpoint: 'http://localhost:4566', // LocalStack endpoint
    forcePathStyle: true // Required for LocalStack
});

const reset = "\x1b[0m";
const bold = "\x1b[1m";
const red = "\x1b[31m";
const yellow = "\x1b[33m";
const green = "\x1b[32m";

async function ensureOpenAIKey() {
    const envFilePath = resolve(join(homedir(), '.openkbs', '.env'));

    let envContent = '';
    try {
        envContent = await fs.readFile(envFilePath, 'utf-8');
    } catch (error) {
        // File does not exist, proceed to create it
    }

    const envLines = envContent.split('\n');
    const openAIKeyLine = envLines.find(line => line.startsWith('OPENAI_KEY='));

    if (!openAIKeyLine) {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        const openAIKey = await new Promise(resolve => {
            rl.question(`\n${green}Enter your OPENAI_KEY: ${reset}`, resolve);
        });

        rl.close();

        if (!envContent.endsWith('\n') && envContent.length > 0) {
            envContent += '\n';
        }
        envContent += `OPENAI_KEY=${openAIKey}\n`;

        await fs.mkdir(resolve(join(homedir(), '.openkbs')), { recursive: true });
        await fs.writeFile(envFilePath, envContent, 'utf-8');
    }
}

export async function loadEnv() {
    await ensureOpenAIKey();

    const envFilePath = resolve(join(homedir(), '.openkbs', '.env'));

    try {
        const envFileContent = readFileSync(envFilePath, 'utf-8');
        const envVariables = envFileContent.split('\n');

        envVariables.forEach(line => {
            const [key, value] = line.split('=');
            if (key && value) {
                process.env[key.trim()] = value.trim();
            }
        });
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.error(`Error: .env file not found at ${envFilePath}`);
        } else {
            console.error(`Error reading .env file: ${error.message}`);
        }
    }
}

function loadOnPremisesChatModels() {
    const jsonFilePath = resolve(join(homedir(), '.openkbs', 'onPremisesChatModels.json'));

    try {
        const jsonFileContent = readFileSync(jsonFilePath, 'utf-8');
        const data = JSON.parse(jsonFileContent);
        return data;
    } catch (error) {
        return null;
    }
}

import {
    BedrockRuntimeClient, InvokeModelWithResponseStreamCommand,
} from "@aws-sdk/client-bedrock-runtime";

const bedrock = new BedrockRuntimeClient({
    credentialDefaultProvider: defaultProvider,
    region: "us-east-1",
});

const bedrockOregon = new BedrockRuntimeClient({
    credentialDefaultProvider: defaultProvider,
    region: "us-west-2",
});

const dynamodb = new AWS.DynamoDB.DocumentClient({
    region: 'us-east-1',
    endpoint: 'http://localhost:4566'
});

// Create an S3 service object
export const sha256 = (txt) => {
    return crypto
        .createHash('sha256')
        .update(txt)
        .digest('hex');
};

export const encryptMessages = (messages, key) => {
    if (!Array.isArray(messages)) {
        throw new Error('Messages should be an array');
    }

    return messages.map(message => {
        if (message.content) {
            return {
                ...message,
                content: encrypt(message.content, key)
            };
        }
        return message;
    });
};

function generateBase58APIKey(length = 32) {
    // Calculate the number of bytes needed to generate the desired length of base58 string
    const numBytes = Math.ceil(length * Math.log(58) / Math.log(256));

    // Generate random bytes
    const randomBytes = crypto.randomBytes(numBytes);

    // Encode the random bytes in base58
    const base58String = bs58.encode(randomBytes);

    // Return the base58 string truncated to the desired length
    return base58String.slice(0, length);
}

export const createAPIKey = async (kbId, APIKeyName, APIKeyPermissions, kbUserId, myUserId, AESKey) => {
    const createdAt = Date.now();

    const apiKey = generateBase58APIKey();

    const item = {
        TableName: 'openkb-kb-apikey',
        Item: {
            kbId,
            apiKey: sha256(apiKey),
            name: APIKeyName,
            permissions: APIKeyPermissions,
            createdAt,
            kbUserId,
            myUserId,
            AESKey
        },
    }

    await dynamodb.put(item).promise();


    return { apiKey };
};

export const getAPIKeys = async (kbId) => {
    const scanResult = await dynamodb.scan({
        TableName: 'openkb-kb-apikey',
        FilterExpression: 'kbId = :kbId',
        ExpressionAttributeValues: {
            ':kbId': kbId,
        },
    }).promise();

    return scanResult?.Items?.map(o => {
        const {AESKey, ...restData} = o;
        return restData
    });
};

export const deleteAPIKey = async (kbId, apiKey) => {
    await dynamodb.delete({
        TableName: 'openkb-kb-apikey',
        Key: {kbId, apiKey},
    }).promise();

    return {apiKey};
};

export const APIKeyPermissions = async (kbId, apiKey) => {
    const params = {
        TableName: 'openkb-kb-apikey',
        Key: {
            kbId,
            apiKey
        }
    };

    try {
        const result = await dynamodb.get(params).promise();

        if (result.Item) {
            return {
                permissions: result.Item.permissions,
                kbUserId: result.Item.kbUserId,
                AESKey: result.Item.AESKey,
            };
        } else {
            throw new Error('API key not found or invalid.');
        }
    } catch (error) {
        console.error('Error verifying API key:', error);
        throw new Error('Error verifying API key.');
    }
};

// Function to encrypt text using the public key
function encryptSecret(text) {
    const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsB7YZD9GmrloeuApJAZV
kG7nPOj6vEXUa1iJFJ9+Xs5lFym47Tqc3s/X+GnIkF2VoNTp3AI3DY3pHFJLT5LR
5OMFrDe6qUU35Z/uZrB4RqSo1jdcqZld8/8Xz8F2fGOPe5yw1Ub5mAQO8Owng0MM
FYdpGlnW5YrXLMyp0YT6UbAYiHC44r1XJZovslxblOrHjzWiOj6On0iBtGK0X2oF
fZ7R/F8auBMIT4a7snDCWiugaEaI09LCPUC01ycnf0Zf1XCVTwI1wb91NAdRvpeN
qAvz3vUNAmxHt1zYiL+WMEYIMJ7YiNwr5cwJpBj+bZJjdmQr/r6+sjTiz7Me0GzM
QQIDAQAB
-----END PUBLIC KEY-----`;
    const buffer = Buffer.from(text, 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
}
export let ChatModels = {};

export const loadChatModels = async () => {
    const loadedOnPremisesChatModels = loadOnPremisesChatModels();
    if (loadedOnPremisesChatModels) ChatModels = loadedOnPremisesChatModels;
    const models = {
        // OpenAI
        "gpt-4o": {
            default: true,
            frontendTokenLimit: 120000,
            searchLimit: 20000,
            vendor: 'openai',
            name: 'GPT 4 Omni',
            size: 'Large',
            vision: {
                type: 'image_url'
            },
            context: 128000,
            isOnPremises: true
        },

        "o1": {
            default: false,
            frontendTokenLimit: 120000,
            searchLimit: 20000,
            vendor: 'openai',
            name: 'OpenAI o1',
            size: 'Large',
            context: 128000,
            isOnPremises: true
        },

        "o1-mini": {
            default: false,
            frontendTokenLimit: 120000,
            searchLimit: 20000,
            vendor: 'openai',
            name: 'OpenAI o1-mini',
            size: 'Medium',
            context: 128000,
            isOnPremises: true
        },
        "gpt-4o-mini": {
            default: false,
            frontendTokenLimit: 120000,
            searchLimit: 20000,
            vendor: 'openai',
            name: 'GPT 4o Mini',
            size: 'Medium',
            vision: {
                type: 'image_url'
            },

            context: 128000,
            isOnPremises: true
        },

        "gpt-4-turbo": {
            frontendTokenLimit: 120000,
            searchLimit: 20000,
            vendor: 'openai',
            name: 'GPT 4 Turbo',
            size: 'Large',
            context: 128000,
            isOnPremises: true
        },

        "gpt-3.5-turbo": {
            frontendTokenLimit: 15000,
            searchLimit: 12000,
            vendor: 'openai',
            name: 'GPT 3.5 Turbo',
            size: 'Medium',
            context: 16000,
            isOnPremises: true
        },

        // Anthropic
        "anthropic.claude-3-5-sonnet-20240620-v1:0": {
            frontendTokenLimit: 190000,
            vendor: 'bedrock',
            name: "Claude 3.5 Sonnet",
            size: 'Large',
            context: 200000,
            isOnPremises: true
        },

        "anthropic.claude-3-opus-20240229-v1:0": {
            frontendTokenLimit: 190000,
            vendor: 'bedrock',
            name: "Claude 3 Opus",
            size: 'Large',
            context: 200000,
            isOnPremises: true
        },

        "anthropic.claude-3-sonnet-20240229-v1:0": {
            frontendTokenLimit: 190000,
            vendor: 'bedrock',
            name: "Claude 3 Sonnet",
            size: 'Medium',
        },
        "anthropic.claude-3-haiku-20240307-v1:0": {
            frontendTokenLimit: 190000,
            vendor: 'bedrock',
            name: "Claude 3 Haiku",
            size: 'Small',
            context: 200000,
            isOnPremises: true
        },


        // Mistral
        "mistral.mistral-large-2402-v1:0": {
            frontendTokenLimit: 30000,
            vendor: 'bedrock',
            name: 'Mistral Large',
            size: 'Large',
            context: 32000,
            isOnPremises: true
        },
        "mistral.mixtral-8x7b-instruct-v0:1": {
            frontendTokenLimit: 30000,
            vendor: 'bedrock',
            name: 'Mixtral-8x7b',
            size: 'Medium',
            context: 32000,
            isOnPremises: true
        },
        "mistral.mistral-7b-instruct-v0:2": {
            frontendTokenLimit: 30000,
            vendor: 'bedrock',
            name: 'Mistral 7b',
            size: 'Small',
            context: 32000,
            isOnPremises: true
        },

        // Meta
        "meta.llama3-70b-instruct-v1:0": {
            frontendTokenLimit: 7500,
            vendor: 'bedrock',
            name: 'Llama 3 70B',
            size: 'Medium',
            context: 8000,
            isOnPremises: true
        },
        "meta.llama3-8b-instruct-v1:0": {
            frontendTokenLimit: 7500,
            vendor: 'bedrock',
            name: 'Llama 3 8B',
            size: 'Small',
            context: 8000,
            isOnPremises: true
        },
        "meta.llama3-1-405b-instruct-v1:0": {
            frontendTokenLimit: 120000,
            vendor: 'bedrock',
            name: 'Llama 3.1 405B',
            size: 'Large',
            context: 120000,
            isOnPremises: true
        },
        "meta.llama3-1-70b-instruct-v1:0": {
            frontendTokenLimit: 120000,
            vendor: 'bedrock',
            name: 'Llama 3.1 70B',
            size: 'Medium',
            context: 120000,
            isOnPremises: true
        }
    }

    // Fetch additional models from localhost
    try {
        const response = await axios.get('http://localhost:8080/models');
        const localModels = response.data.models;

        for (const vendor in localModels) {
            if (vendor === 'meta-llama') {
                for (const modelName in localModels[vendor]) {
                    const modelKey = `localhost.${vendor}.${modelName}`;

                    let size = 'Unknown';
                    const sizeMatch = modelName.match(/(\d+)(B)/);
                    if (sizeMatch) {
                        const sizeValue = parseInt(sizeMatch[1], 10);
                        if (sizeValue >= 7 && sizeValue < 30) {
                            size = 'Small';
                        } else if (sizeValue >= 30 && sizeValue < 70) {
                            size = 'Medium';
                        } else if (sizeValue >= 70) {
                            size = 'Large';
                        }
                    }

                    models[modelKey] = {
                        frontendTokenLimit: 120000,
                        vendor: 'localhost',
                        name: modelName.replace(/Instruct$/, 'Inst'),
                        size: size,
                        context: 120000,
                        isOnPremises: true
                    };
                    console.log(modelName, ' local model loaded!')
                }
            }
        }
    } catch (error) {
        console.error('Failed to fetch models from localhost:', error.message);
    }

    const openaiKeyDefined = typeof process.env.OPENAI_KEY !== 'undefined';
    const bedrockKeyDefined = typeof process.env.BEDROCK_KEY !== 'undefined';

    // Add localhost models first
    const localhostModels = Object.entries(models).filter(([_, model]) => model.vendor === 'localhost');
    if (localhostModels.length > 0) {
        ChatModels = Object.fromEntries(localhostModels);
    }

    // Add OpenAI models if the key is defined
    if (openaiKeyDefined) {
        const openaiModels = Object.entries(models).filter(([_, model]) => model.vendor === 'openai');
        if (openaiModels.length > 0) {
            ChatModels = { ...ChatModels, ...Object.fromEntries(openaiModels) };
        }
    }

    // Add Bedrock models if the key is defined
    if (bedrockKeyDefined) {
        const bedrockModels = Object.entries(models).filter(([_, model]) => model.vendor === 'bedrock');
        if (bedrockModels.length > 0) {
            ChatModels = { ...ChatModels, ...Object.fromEntries(bedrockModels) };
        }
    }

};

export function approximateTokenSize(input) {
    const WHITESPACE_RE = /^\s+$/
    const CJK_RE = /[\u4E00-\u9FFF\u3400-\u4DBF\u3000-\u303F\uFF00-\uFFEF\u30A0-\u30FF\u2E80-\u2EFF\u31C0-\u31EF\u3200-\u32FF\u3300-\u33FF\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F\uA960-\uA97F\uD7B0-\uD7FF]/
    const NUMERIC_SEQUENCE_RE = /[\d.,]+/
    const PUNCTUATION_RE = /[.,!?;'"„“”‘’\-(){}[\]<>:/\\|@#$%^&*+=`~]/
    // Pattern for spoken words, including accented characters
    const ALPHANUMERIC_RE = /^[a-zA-Z0-9\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u00FF]+$/

    const DEFAULT_AVERAGE_CHARS_PER_TOKEN = 6
    // For languages similar to English, define a rough average
    // number of characters per token
    const LANGUAGE_METRICS = [
        { regex: /[äöüßÄÖÜẞ]/, averageCharsPerToken: 3 },
    ]

    // Split by whitespace, punctuation, and other special characters
    const roughTokens = input
        .split(/(\s+|[.,!?;'"„“”‘’\-(){}[\]<>:/\\|@#$%^&*+=`~]+)/)
        .filter(Boolean)

    let tokenCount = 0
    for (const token of roughTokens) {
        let averageCharsPerToken;
        for (const language of LANGUAGE_METRICS) {
            if (language.regex.test(token)) {
                averageCharsPerToken = language.averageCharsPerToken
                break
            }
        }

        if (WHITESPACE_RE.test(token)) {
            // Don't count whitespace as a token
            continue
        }
        else if (CJK_RE.test(token)) {
            // For CJK languages, each character is usually a separate token
            tokenCount += Array.from(token).length
        }
        else if (NUMERIC_SEQUENCE_RE.test(token)) {
            // Numeric sequences are often a single token, regardless of length
            tokenCount += 1
        }
        else if (token.length <= 3) {
            // Short tokens are often a single token
            tokenCount += 1
        }
        else if (PUNCTUATION_RE.test(token)) {
            // Punctuation is often a single token, but multiple punctuations are often split
            tokenCount += token.length > 1 ? Math.ceil(token.length / 2) : 1
        }
        else if (ALPHANUMERIC_RE.test(token) || averageCharsPerToken) {
            // Use language-specific average characters per token or default to average
            tokenCount += Math.ceil(token.length / (averageCharsPerToken ?? DEFAULT_AVERAGE_CHARS_PER_TOKEN))
        }
        else {
            // For other characters (like emojis or special characters), or languages
            // like Arabic, Hebrew and Greek, count each as a token
            tokenCount += Array.from(token).length
        }
    }

    return tokenCount
}


function countTokens(text) {
    return approximateTokenSize(text)
}

export async function handleOnResponse({count, res, payload, sendMessages, responseHandler, kbData, AESKey, chatId}) {
    if (hasCode(responseHandler)) {
        const currentId = ++count.id;
        await send(res, { id: currentId, content: JSON.stringify({ _meta_type: 'EVENT_STARTED', _event: 'onResponse' }), role: 'system' });
        try {
            let response = await executeHandler(responseHandler, {
                payload: {
                    ...payload,
                    messages: [...payload.messages, {role: 'system', content: sortAndConcatenateMessages(sendMessages)}],
                    chatId
                }
            }, kbData, AESKey);

            const content = typeof response === "string" && response.length
                ? response
                : JSON.stringify({...response, _meta_type: "EVENT_FINISHED", _event: 'onResponse'})

            const currentId = ++count.id;
            await send(res, { id: currentId, content, role: 'system' });
        } catch (e) {
            const currentId = ++count.id;
            await send(res, { id: currentId, content: JSON.stringify({error: e.message, _meta_type: "EVENT_FINISHED", _event: 'onResponse', _meta_actions: ['REQUEST_CHAT_MODEL']}), role: 'system' });
        }
    }
}

export function countTotalTokens(messages) {
    let totalTokens = 0;
    messages.forEach(message => {
        Object.keys(message).forEach(key => {
            if (key && message?.[key]) totalTokens += countTokens(message[key].toString());
        });
    });
    return totalTokens;
}

export const chatStream = async (config, on_start, on_delta, on_stop, on_error, on_close) => {
    const { payload, kbData } = config;
    let isFirst = true;

    const model = payload.model;
    const chatVendor = ChatModels?.[model]?.vendor

    if (chatVendor !== 'bedrock') {
        const modelResponse = await chatStreamHTTP(
            getVendorRequest({ model }),
            getVendorPayload(payload, {...kbData, model}),
            new AbortController()
        )
        let partialMessage = '';
        let output = '';
        const inputTokens = countTotalTokens(payload?.messages);
        modelResponse.on('data', async (data) => {
            const lines = data.toString().split('\n').filter(line => line.trim() !== '');
            for (const line of lines) {
                const outputTokens = countTokens(output)
                partialMessage += line;
                partialMessage = partialMessage.replace(/^data: /, '')
                if (partialMessage === '[DONE]') {
                    on_stop({inputTokens, outputTokens})
                } else {
                    try {
                        const parsed = JSON.parse(partialMessage);
                        let data = chatVendor === 'openai' ? parsed.choices[0].delta : parsed;
                        if (Object.keys(data)?.length) {
                            if (isFirst) {
                                on_start({role: (data?.role || 'assistant')})

                                if (data?.content) on_delta({content: data?.content}); // handle Llama where the stream starts without role
                            } else {
                                on_delta(data)
                            }
                            isFirst = false
                        }
                        partialMessage = '';
                        output += data?.content
                    } catch (error) {
                        const validModelResponse = parseJSON(partialMessage);
                        const { choices, usage, model } = validModelResponse || {};
                        const firstChoice = choices?.[0]?.message;
                        if (
                            model &&
                            firstChoice?.content &&
                            usage?.prompt_tokens &&
                            usage?.completion_tokens
                        ) {
                            const role = firstChoice.role || 'assistant';
                            await on_start({ role });
                            await on_delta(firstChoice);
                            await on_stop({
                                inputTokens: usage.prompt_tokens,
                                outputTokens: usage.completion_tokens
                            });
                        } else {
                            // console.log('Accumulating partial message for JSON parsing', partialMessage);
                        }
                    }
                }

            }
        });

        modelResponse.on('error', async (error) => on_error(error))
        modelResponse.on('close', async (e) => on_close(e))
    } else if (chatVendor === 'bedrock') {
        const myPayload = getVendorPayload(payload, {...kbData, model});
        const command = new InvokeModelWithResponseStreamCommand({
            contentType: "application/json",
            body: JSON.stringify(myPayload),
            modelId: payload?.model
        });

        let bedrockClient = [
            "anthropic.claude-3-opus-20240229-v1:0",
            "meta.llama3-1-405b-instruct-v1:0",
            "meta.llama3-1-70b-instruct-v1:0",
        ].includes(payload?.model) ? bedrockOregon : bedrock;

        const apiResponse = await bedrockClient.send(command);
        let isFirst = true;
        for await (const item of apiResponse.body) {
            const chunk = JSON.parse(new TextDecoder().decode(item.chunk.bytes));
            if (payload?.model?.startsWith('anthropic.claude')) {
                const chunk_type = chunk.type;
                if (chunk_type === "message_start") {
                    on_start(chunk?.message?.role)
                } else if (chunk_type === "content_block_delta") {
                    on_delta({content: chunk?.delta?.text})
                } else if (chunk_type === "message_stop") {
                    const metrics = chunk["amazon-bedrock-invocationMetrics"];
                    on_stop({
                        inputTokens: metrics.inputTokenCount,
                        outputTokens: metrics.outputTokenCount
                    })
                }
            } else if (payload?.model?.startsWith('mistral.')) {
                if (isFirst) on_start('assistant')
                if (chunk?.outputs?.length) {
                    for (let output of chunk.outputs) {
                        if (output?.stop_reason === 'stop') {
                            const metrics = chunk["amazon-bedrock-invocationMetrics"];
                            on_stop({
                                inputTokens: metrics.inputTokenCount,
                                outputTokens: metrics.outputTokenCount
                            })
                        } else if (output?.text) {
                            on_delta({content: output.text})
                        }
                    }
                }
            } else if (payload?.model?.startsWith('meta.llama3')) {
                if (isFirst) on_start('assistant')
                if (chunk?.generation?.length) {
                    on_delta({content: chunk?.generation})
                } else if (chunk?.stop_reason === 'stop') {
                    const metrics = chunk["amazon-bedrock-invocationMetrics"];
                    on_stop({
                        inputTokens: metrics.inputTokenCount,
                        outputTokens: metrics.outputTokenCount
                    })
                }
            }
            isFirst = false;
        }
    }
};

export const chatStreamHTTP = async ({chatEndpoint, method, headers}, payload, controller) => {
    const { signal } = controller;

    return new Promise((resolve, reject) => {
        const urlObj = new URL(chatEndpoint);

        const options = {
            hostname: urlObj.hostname,
            path: urlObj.pathname + (urlObj.search ? urlObj.search : ''),
            port: urlObj.port,
            search: urlObj.search,
            method,
            headers,
            signal
        };

        const module =  urlObj.protocol === 'http:' ? http : https;

        const req = module.request(options, (res) => {
            resolve(res);
        });

        req.on('error', (error) => {
            if (error.name === 'AbortError') {
                console.log('Request aborted');
            } else {
                reject(error);
            }
        });

        req.write(JSON.stringify(payload));
        req.end();
    });
};

export function calculateTotalProperty(benchmarkData) {
    let total = 0;

    for (let key in benchmarkData) {
        total += benchmarkData[key];
    }

    benchmarkData.total = total;

    return benchmarkData;
}

export const decrypt = (ciphertext, key) => {
    if (ciphertext == null) {
        return ciphertext;
    }

    if (key == null) {
        throw new Error('Either ciphertext or key is null');
    }

    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    return bytes.toString(CryptoJS.enc.Utf8);
};

export const encrypt = (plaintext, key) => {
    if (plaintext == null) {
        return plaintext;
    }

    if (key == null) {
        throw new Error('Either plaintext or key is null');
    }

    const ciphertext = CryptoJS.AES.encrypt(plaintext, key).toString();
    return ciphertext;
};

const OPENKBS_AUTH_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr51Lj1jQUXTiUKkS6/ez
YfV+cRXz1g5OhU/pVghMonDeWSb9yNjNu1HBI5JFj3peEELpqV3TYsZLIRCFlKOb
wmXoVgAEcb+hU77pV0yjXcUDwiIFakrb1rfmBm4JXcRTL2ps0LjD2acpU4slxxJC
dZTkzrIHDV9+IOYqQHFUgMxdP2xi8Tq/pGhkoYl62ChjOH1L3sZIre93hgveNizg
ls2xDM/eeDs/Ws9M2M46Wv2opfke+gEvlKNT5gKQ++wqnoXToPzDCpEB+Np2cu8p
a3Iu2UL4i+R6zTdkxyhuOUlBTiUbLCGXJedqZzHHV2+om3cX4W9WBhJd+OjdP2kj
CQIDAQAB
-----END PUBLIC KEY-----`;
const rsaKey = new NodeRSA();
rsaKey.importKey(OPENKBS_AUTH_PUBLIC_KEY, 'public');


export function hasCode(code) {
    return code && !/^\s*$/.test(code);
}

// Fetch the file from S3
async function fetchFileFromS3(bucket, key) {
    try {
        const data = await s3Client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
        const stream = data.Body;
        const chunks = [];
        for await (const chunk of stream) {
            chunks.push(chunk);
        }
        return Buffer.concat(chunks).toString('utf-8');
    } catch (err) {
        return ''
    }
}

export async function fetchOnAddMessagesHandler(kbId) {
    let code = '';
    try {
        code = await fetchFileFromS3('openkbs-files', `functions/${kbId}/Events/dist/onAddMessages/index.js`);
    } catch(e) {
        code = null;
    }
    return code;
}

export async function fetchOnRequestHandler(kbId) {
    let code = '';
    try {
        code = await fetchFileFromS3('openkbs-files', `functions/${kbId}/Events/dist/onRequest/index.js`);
    } catch(e) {
        code = null;
    }
    return code;
}

export async function fetchOnResponseHandler(kbId) {
    let code = '';
    try {
        code = await fetchFileFromS3('openkbs-files', `functions/${kbId}/Events/dist/onResponse/index.js`);
    } catch(e) {
        code = null;
    }
    return code;
}

export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export const getItems = async (kbId, itemIds, AESKey) => {
    const params = {
        RequestItems: {
            'openkb-item': {
                Keys: itemIds.map(itemId => ({kbId, itemId})),
                ProjectionExpression: 'body, itemId, totalTokens',
            },
        },
    };

    try {
        const result = await dynamodb.batchGet(params).promise();
        const items = result.Responses['openkb-item'];
        if (items.length === itemIds.length) {
            const decryptedItems = [];
            let i = 0;
            for (let p of items) {
                i++
                if (p.body == null || AESKey == null) {
                    console.error('Either body, or AESKey is null', p.body, AESKey);
                    continue;
                }

                const body = await decrypt(p.body, AESKey);
                const totalTokens = p.totalTokens;

                let totalTokens2 = countTokens(`\n\n###\n\nContent:\n${body}`);

                decryptedItems.push({totalTokens, totalTokens2, body, i});
            }

            return decryptedItems;
        } else {
            throw new Error('Some items not found');
        }
    } catch (error) {
        console.error('Error fetching items:', error);
        throw error;
    }
}

export function getFiltered(items, maxTokens) {
    if (!items) return [];
    const filtered = [];
    let currentTokens = 0;

    for (const item of items) {
        if (currentTokens + item._source.totalTokens <= maxTokens) {
            filtered.push(item);
            currentTokens += item._source.totalTokens;
        } else {
            break;
        }
    }

    return filtered;
}

export const findKnn = async () => {
    return {
        filtered: [],
        all: [],
        benchmarkData: {}
    } // @Todo openSearch semantic search implementation
};


export function stripInputLabelsAndValues(inputText) {
    // Regular expressions to match the InputLabel and InputValue patterns
    const inputLabelRegex = /^\$InputLabel\s*=\s*""".*?"""\s*$/gm;
    const inputValueRegex = /^\$InputValue\s*=\s*""".*?"""\s*$/gm;

    // Remove lines matching the patterns
    let strippedText = inputText
        .replace(inputLabelRegex, '')
        .replace(inputValueRegex, '');

    return strippedText;
}

export function buildSystemContent(decryptedKBInstructions, instructionSuffixString, kbData) {
    let output = '';
    if (kbData?.sharedWithUsers?.values?.length) output += `
User IDs like 'User_51d1234b609471c7' identify the users writing in this chat.
They are not part of the message content.
Any text below referring to 'userId' do not relate to these annotations, as they are invisible to the chat users.
Avoid discussing these IDs.
`;
    if (decryptedKBInstructions) output += `\n\n${stripInputLabelsAndValues(decryptedKBInstructions)}\n\n`;
    if (instructionSuffixString) output += `\n\n${instructionSuffixString}\n\n`
    return output;
}

export function sortAndConcatenateMessages(messages) {
    messages.sort((a, b) => a.id - b.id);

    let concatenatedText = '';
    let previousId = null;
    for (const message of messages) {
        if (message.content && (previousId === null || message.id === previousId + 1)) {
            concatenatedText += message.content;
            previousId = message.id;
        }
    }

    return concatenatedText;
}

export async function executeHandler(userCode, event, kbData, AESKey) {
    const walletPrivateKey = kbData?.walletPrivateKey;
    const walletPublicKey = kbData?.walletPublicKey;
    const accountId = kbData?.accountId;

    try {
        const response = await axios.post(`http://localhost:38595`, {
            walletPrivateKey,
            walletPublicKey,
            accountId,
            userCode,
            AESKey,
            event,
            variables: kbData?.variables && Object.keys(kbData?.variables)?.length > 0 ? kbData.variables : undefined
        });

        return response.data;
    } catch (error) {
        if (error?.response?.data?.error) throw new Error(error?.response?.data?.error);
        console.error("Error calling external function:", error.message);
        throw new Error("Failed to call external function: " + error.message);
    }
}

export const verifyToken = async (token) => {
    try {
        const verifyAsync = promisify(jwt.verify).bind(jwt);
        const decoded = await verifyAsync(token, rsaKey.exportKey('public'));
        return decoded;
    } catch (err) {
        throw new Error('Invalid token');
    }
};

export async function getAllUnreadMessages(userId, kbId) {
    const userIdKbId = `${userId}#${kbId}`;
    const params = {
        TableName: "openkb-unread-messages",
        KeyConditionExpression: "userId_kbId = :userIdKbId",
        ExpressionAttributeValues: {
            ":userIdKbId": userIdKbId
        }
    };

    try {
        const result = await dynamodb.query(params).promise();
        // console.log("Unread messages retrieved successfully", result.Items);
        return result.Items; // Return the unread messages
    } catch (error) {
        console.error("Error retrieving unread messages:", error);
        throw error; // Rethrow the error to handle it in the caller function
    }
}

export async function getUnreadMessages(userId, kbId, chatId) {
    const userIdKbId = `${userId}#${kbId}`;
    const params = {
        TableName: "openkb-unread-messages",
        Key: {
            userId_kbId: userIdKbId,
            chatId: chatId
        }
    };

    try {
        const result = await dynamodb.get(params).promise();
        if (result.Item) {
            return result.Item; // Return the specific unread message
        } else {
            return null; // Return null if no message was found
        }
    } catch (error) {
        console.error("Error retrieving the unread message:", error);
        throw error; // Rethrow the error to handle it in the caller function
    }
}

export async function deleteUnreadMessages(userId, kbId, chatId) {
    const userIdKbId = `${userId}#${kbId}`;
    const params = {
        TableName: "openkb-unread-messages",
        Key: {
            userId_kbId: userIdKbId,
            chatId: chatId
        }
    };

    try {
        const result = await dynamodb.delete(params).promise();
    } catch (error) {
        console.error("Error deleting unread message:", error);
    }
}

function msgMapper({ content, msgId, role, userId, reactions, updatedAt }) {
    // Transform reactions from a set to the desired object structure
    const transformedReactions = reactions ? reactions.values.reduce((acc, reaction) => {
        const [encodedUserId, emojiId] = Buffer.from(reaction, 'base64').toString().split('###');
        if (!acc[emojiId]) {
            acc[emojiId] = {};
        }
        acc[emojiId][encodedUserId] = true; // Use true as a placeholder value
        return acc;
    }, {}) : {};

    return { content, msgId, role, userId, reactions: transformedReactions, updatedAt };
}

// OK
export const getChatMessages = async ({ chatId, kbId, myUserId, limit, lastEvaluatedKey = null }) => {
    limit = Math.min((limit || 25), 100000);
    let params = {
        TableName: 'openkb-chat-messages',
        KeyConditionExpression: 'chatId = :chatId',
        FilterExpression: 'kbId = :kbId',
        ExpressionAttributeValues: {
            ':chatId': chatId,
            ':kbId': kbId,
        },
        Limit: limit,
        ScanIndexForward: false,
        ExclusiveStartKey: lastEvaluatedKey,
    };

    try {
        const unreadCheckPromise = getUnreadMessages(myUserId, kbId, chatId);
        let firstFetchPromise = dynamodb.query(params).promise();

        // Wait for both promises to resolve
        let [unreadMessage, firstFetchResult] = await Promise.all([unreadCheckPromise, firstFetchPromise]);
        // If there are unread messages, delete them
        if (unreadMessage) await deleteUnreadMessages(myUserId, kbId, chatId);

        return {
            items: firstFetchResult?.Items?.length,
            lastEvaluatedKey: firstFetchResult?.LastEvaluatedKey || null,
            messages: firstFetchResult.Items.map(msgMapper).reverse()
        };
    } catch (error) {
        console.error('Error getting chat messages:', error);
        // throw error;
    }
};

export const deleteChat = async ({ kbId, chatId }) => {
    const getChatParams = {
        TableName: 'openkb-kb-chats',
        Key: { kbId, chatId },
    };

    const chat = await dynamodb.get(getChatParams).promise();

    const deleteChatParams = {
        TableName: 'openkb-kb-chats',
        Key: { kbId, chatId },
    };

    await dynamodb.delete(deleteChatParams).promise();

    const event = {
        eventName: 'REMOVE',
        OldImage: chat.Item,
        tableName: 'openkb-kb-chats',
    };

    await sendToAllConnections(kbId, event);

    await deleteAllMessagesForChat(chatId);

    return { chatId };
};

// OK
const deleteAllMessagesForChat = async (chatId) => {
    let hasMoreMessages = true;
    let startKey = null;

    while (hasMoreMessages) {

        // Step 1: Query messages for the chatId
        const queryMessagesParams = {
            TableName: 'openkb-chat-messages',
            KeyConditionExpression: 'chatId = :chatId',
            ExpressionAttributeValues: {
                ':chatId': chatId,
            },
            ExclusiveStartKey: startKey,
        };

        const messagesResult = await dynamodb.query(queryMessagesParams).promise();

        const messages = messagesResult.Items;

        // Step 2: Delete messages in batches
        for (let i = 0; i < messages.length; i += 25) {
            const batch = messages.slice(i, i + 25);
            const deleteRequests = batch.map((message) => ({
                DeleteRequest: {
                    Key: {
                        chatId: message.chatId,
                        msgId: message.msgId,
                    },
                },
            }));

            const batchWriteParams = {
                RequestItems: {
                    'openkb-chat-messages': deleteRequests,
                },
            };

            await dynamodb.batchWrite(batchWriteParams).promise();
        }

        // Check if there are more messages to fetch and delete
        hasMoreMessages = !!messagesResult.LastEvaluatedKey;
        startKey = messagesResult.LastEvaluatedKey;
    }
};

export const updateChat = async ({ kbId, chatId, title, chatInstructions, chatIcon, chatModel }) => {
    const updatedAt = Date.now();

    let updateExpression = 'set updatedAt = :u';
    let expressionAttributeValues = {
        ':u': updatedAt,
    };

    if (title !== undefined) {
        updateExpression += ', title = :t';
        expressionAttributeValues[':t'] = title;
    }

    if (chatInstructions !== undefined) {
        updateExpression += ', chatInstructions = :ci';
        expressionAttributeValues[':ci'] = chatInstructions;
    }

    if (chatIcon !== undefined) {
        updateExpression += ', chatIcon = :chi';
        expressionAttributeValues[':chi'] = chatIcon;
    }

    if (chatModel !== undefined) {
        updateExpression += ', chatModel = :cm';
        expressionAttributeValues[':cm'] = chatModel;
    }

    const params = {
        TableName: 'openkb-kb-chats',
        Key: { kbId, chatId },
        UpdateExpression: updateExpression,
        ExpressionAttributeValues: expressionAttributeValues,
        ReturnValues: 'ALL_NEW',
    };

    const result = await dynamodb.update(params).promise();

    const event = {
        eventName: 'MODIFY',
        NewImage: result.Attributes,
        tableName: 'openkb-kb-chats',
    };

    await sendToAllConnections(kbId, event);
};

// OK
export const chatAddMessages = async ({ chatId, messages, kbId, kbDataLoadedBeforeAction }) => {
    const addMessagesHandler = await fetchOnAddMessagesHandler(kbId);
    let messagesToAdd = messages;

    try {
        if (addMessagesHandler && hasCode(addMessagesHandler)) {
            const kbData = kbDataLoadedBeforeAction;
            const AESKey = kbData.key;

            let decryptedMessages = messagesToAdd.map(o => ({ ...o, content: decrypt(o.content, AESKey) }));
            decryptedMessages = await executeHandler(addMessagesHandler, { payload: { messages: decryptedMessages, chatId } }, kbData, AESKey);
            messagesToAdd = decryptedMessages.map(o => ({ ...o, content: encrypt(o.content, AESKey) }));
        }

        if (messagesToAdd?.length) {
            await Promise.all(messagesToAdd.map(async (message) => {
                const msgId = message.msgId || generateMsgId();
                const messageParams = {
                    TableName: 'openkb-chat-messages',
                    Item: { chatId, msgId, kbId, ...message },
                };
                await dynamodb.put(messageParams).promise();

                const event = {
                    eventName: 'INSERT',
                    NewImage: messageParams.Item,
                    tableName: 'openkb-chat-messages',
                };

                await sendToAllConnections(kbId, event);
            }));
        }
    } catch (e) {
        return messagesToAdd;
    }

    return messagesToAdd;
};


function base64Encode(value) {
    return Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function chatMessageAddReaction({ kbId, chatId, msgId, userId, emojiId }) {
    const reactionKey = base64Encode(`${userId}###${emojiId}`);

    const params = {
        TableName: 'openkb-chat-messages',
        Key: {
            'chatId': chatId,
            'msgId': msgId,
        },
        UpdateExpression: 'ADD reactions :reaction',
        ExpressionAttributeValues: {
            ':reaction': dynamodb.createSet([reactionKey]),
            ':kbIdVal': kbId,
        },
        ConditionExpression: 'kbId = :kbIdVal',
        ReturnValues: 'ALL_NEW',
    };

    try {
        const data = await dynamodb.update(params).promise();

        const event = {
            eventName: 'MODIFY',
            NewImage: data.Attributes,
            tableName: 'openkb-chat-messages',
        };

        await sendToAllConnections(kbId, event);

        return { success: true, data: data };
    } catch (error) {
        console.error('Unable to add reaction. Error JSON:', JSON.stringify(error, null, 2));
        if (error.code === 'ConditionalCheckFailedException') {
            throw new Error('kbId does not match for the message being reacted to');
        }
        throw new Error('Unable to add reaction');
    }
}


export async function chatMessageRemoveReaction({ kbId, chatId, msgId, userId, emojiId }) {
    const reactionKey = base64Encode(`${userId}###${emojiId}`);

    const params = {
        TableName: 'openkb-chat-messages',
        Key: {
            'chatId': chatId,
            'msgId': msgId,
        },
        UpdateExpression: 'DELETE reactions :reaction',
        ExpressionAttributeValues: {
            ':reaction': dynamodb.createSet([reactionKey]),
            ':kbIdVal': kbId,
        },
        ConditionExpression: 'kbId = :kbIdVal',
        ReturnValues: 'ALL_NEW',
    };

    try {
        const data = await dynamodb.update(params).promise();

        const event = {
            eventName: 'MODIFY',
            NewImage: data.Attributes,
            tableName: 'openkb-chat-messages',
        };

        await sendToAllConnections(kbId, event);

        return { success: true, data: data };
    } catch (error) {
        console.error('Unable to remove reaction. Error JSON:', JSON.stringify(error, null, 2));
        if (error.code === 'ConditionalCheckFailedException') {
            throw new Error('kbId does not match for the message from which the reaction is being removed');
        }
        throw new Error('Unable to remove reaction');
    }
}

export async function chatEditMessage({ kbId, chatId, msgId, content }) {
    const updatedAt = +new Date();
    const params = {
        TableName: 'openkb-chat-messages',
        Key: {
            'chatId': chatId,
            'msgId': msgId,
        },
        UpdateExpression: 'set content = :c, updatedAt = :u',
        ExpressionAttributeValues: {
            ':c': content,
            ':u': updatedAt,
            ':kbIdVal': kbId,
        },
        ConditionExpression: 'kbId = :kbIdVal',
        ReturnValues: 'ALL_NEW',
    };

    try {
        const data = await dynamodb.update(params).promise();

        const event = {
            eventName: 'MODIFY',
            NewImage: data.Attributes,
            tableName: 'openkb-chat-messages',
        };

        await sendToAllConnections(kbId, event);

        return { success: true, data: data };
    } catch (error) {
        console.error('Unable to edit message. Error JSON:', JSON.stringify(error, null, 2));
        if (error.code === 'ConditionalCheckFailedException') {
            throw new Error('kbId does not match for the message being edited ' + kbId);
        }
        throw new Error('Unable to edit message');
    }
}


export const chatDeleteMessage = async ({ chatId, msgId, kbId }) => {
    const getMessageParams = {
        TableName: 'openkb-chat-messages',
        Key: { chatId, msgId },
    };

    const message = await dynamodb.get(getMessageParams).promise();

    const deleteParams = {
        TableName: 'openkb-chat-messages',
        Key: {
            chatId,
            msgId,
        },
        ConditionExpression: 'kbId = :kbId',
        ExpressionAttributeValues: {
            ':kbId': kbId,
        },
    };

    try {
        await dynamodb.delete(deleteParams).promise();

        const event = {
            eventName: 'REMOVE',
            OldImage: message.Item,
            tableName: 'openkb-chat-messages',
        };

        await sendToAllConnections(kbId, event);
    } catch (error) {
        if (error.code === 'ConditionalCheckFailedException') {
            console.error('Message not found or kbId mismatch');
        } else {
            throw error;
        }
    }
};

const generateMsgId = () => `${+new Date()}-${Math.floor(100000 + Math.random() * 900000)}`
const generateChatId = () => `${+new Date()}-${Math.floor(100000 + Math.random() * 900000)}`
export const createChat = async ({ kbId, title, messages, chatId }) => {
    chatId = chatId || generateChatId();
    const chatParams = {
        TableName: 'openkb-kb-chats',
        Item: {
            kbId,
            chatId,
            title,
            updatedAt: Date.now(),
        },
        ConditionExpression: 'attribute_not_exists(chatId)',
    };

    await dynamodb.put(chatParams).promise();

    const event = {
        eventName: 'INSERT',
        NewImage: chatParams.Item,
        tableName: 'openkb-kb-chats',
    };

    await sendToAllConnections(kbId, event);

    await Promise.all(messages.map(async (message) => {
        const msgId = message.msgId || generateMsgId();
        const messageParams = {
            TableName: 'openkb-chat-messages',
            Item: { chatId, msgId, kbId, ...message },
        };
        await dynamodb.put(messageParams).promise();

        const messageEvent = {
            eventName: 'INSERT',
            NewImage: messageParams.Item,
            tableName: 'openkb-chat-messages',
        };

        await sendToAllConnections(kbId, messageEvent);
    }));

    return { chatId };
};

export const listChats = async (kbId) => {
    const params = {
        TableName: 'openkb-kb-chats',
        IndexName: 'kbId-updatedAt-index',
        KeyConditionExpression: 'kbId = :kbId',
        ExpressionAttributeValues: {
            ':kbId': kbId,
        },
        ScanIndexForward: false,
        Limit: 25,
    };

    try {
        const result = await dynamodb.query(params).promise();
        return result.Items;
    } catch (error) {
        console.error('Error listing chats:', error);
    }
}

export const getChat = async (kbId, chatId) => {
    const params = {
        TableName: 'openkb-kb-chats',
        Key: {
            kbId: kbId,
            chatId: chatId,
        },
    };

    try {
        const result = await dynamodb.get(params).promise();
        return result.Item;
    } catch (error) {
        console.error('Error getting chat details:', error);
        throw error;
    }
};

export let setHead = (res, statusCode) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, transaction-jwt',
        'Access-Control-Allow-Methods': 'OPTIONS,POST,GET',
        'Content-Type': 'application/json',
        "Access-Control-Max-Age": 600
    }

    res.writeHead(statusCode, headers)
}

export const send = async (res, msg) => {
    let messageString = JSON.stringify(msg);

    if (!messageString.length || messageString.length < 16000) {
        return res.write(messageString + '\n');
    }

    const chunkSize = 16000;

    for (let i = 0; i < messageString.length; i += chunkSize) {
        const chunk = messageString.substring(i, i + chunkSize)
        res.write(chunk);
        await sleep(1)
    }

    res.write('\n');
};

export async function warmup(res) {
    setHead(res, 200);
    for (let i = 0; i < 10; i++) {
        await send(res, {statusCode: 200, i});
        await sleep(25);
    }

    res.end()
}

export async function handleNoMessages(res) {
    await send(res, {error: 'no messages provided'});
    res.end()
}

export async function handleEmptyBody(res) {
    setHead(res, 200);
    await send(res, {statusCode: 200, error: 'Empty request'});
    res.end()
}

const openaiReasoningModels = ['o1-mini', 'o1', 'o1-preview'];
function formatMessagesPerModel(model, messages) {
    if (openaiReasoningModels.includes(model)) {
        return messages.map(message => {
            if (message.role === 'system') {
                return { ...message, role: 'user' };
            }
            return message;
        });
    }
    else if (model?.startsWith('anthropic.claude')) {
        const updatedMessages = messages.map(msg => ({
            ...msg,
            role: msg.role === 'system' ? 'user' : msg.role
        })).filter(msg => msg?.content);

        // Then, concatenate consecutive 'user' messages
        const formatedMessages = updatedMessages.reduce((acc, msg, index, arr) => {
            if (msg.role === 'user') {
                if (acc.length > 0 && acc[acc.length - 1].role === 'user') {
                    // Concatenate content with the previous 'user' message
                    acc[acc.length - 1].content += `\n${msg.content}`;
                } else {
                    // Push new 'user' message onto the accumulator
                    acc.push(msg);
                }
            } else {
                // For 'assistant' messages, just push them onto the accumulator
                acc.push(msg);
            }
            return acc;
        }, []).map(msg => {
            return {
                role: msg?.role,
                content: [
                    { type: "text", text: msg?.content }
                ]
            }
        });

        return formatedMessages;
    }

    return messages

}

function convertMessagesToMistralPrompt(messages) {
    let prompt = '<s>';
    messages.forEach((message, index) => {
        if (message.role === 'user') {
            prompt += `[INST] ${message.content} [/INST]`;
        }
        else if (message.role === 'system') {
            // Handle system messages, possibly as plain text or wrapped in a special tag if needed
            prompt += `[INST] system: ${message.content} [/INST]`;
        }
        else if (message.role === 'assistant') {
            prompt += `${message.content}`;
            // Add the end of sentence token only if it's not the last message or if the next message is from the user
            if (messages[index + 1].role === 'user') {
                prompt += '</s>';
            }
        }
    });
    return prompt;
}

function convertMessagesToLlamaPrompt(messages) {
    let prompt = '<|begin_of_text|>';
    messages.forEach((message, index) => {
        if (message.role === 'system') {
            prompt += `<|start_header_id|>system<|end_header_id|>\n${message.content}<|eot_id|>`;
        } else if (message.role === 'user') {
            prompt += `<|start_header_id|>user<|end_header_id|>\n${message.content}<|eot_id|>`;
        } else if (message.role === 'assistant') {
            prompt += `<|start_header_id|>assistant<|end_header_id|>\n${message.content}<|eot_id|>`;
        }
    });
    prompt += '<|start_header_id|>assistant<|end_header_id|>\n\n';
    // console.log('prompt', prompt)
    return prompt;
}

const parseJSON = (jsonString) => {
    try {
        return JSON.parse(jsonString);
    } catch (error) {
        return null;
    }
};

export const getVendorPayload = (payload, {model, sharedWithUsers, accountId}) => {
    const chatVendor = ChatModels?.[model]?.vendor

    const processMessages = (messages) => {
        return messages.map(({userId, content, msgId, ...rest}) => {

            let processedContent;

            const parsedContent = parseJSON(content);
            if (parsedContent && Array.isArray(parsedContent) && parsedContent.find(o => o?.type === 'image_url' && o?.image_url?.url)) {
                processedContent = parsedContent.map(o => {
                    if (o.type === 'text') {
                        return {
                            type: 'text',
                            text: (userId && sharedWithUsers?.values?.length) ? `${userId}: ${o.text}` : o.text
                        };
                    } else {
                        return o;
                    }
                });
            } else {
                processedContent = (userId && sharedWithUsers?.values?.length) ? `${userId}: ${content}` : content;
            }

            return {
                content: processedContent,
                role: rest.role,
            }
        })
    }


    // Common structure for messages
    const messages = formatMessagesPerModel(payload?.model, processMessages(payload?.messages));

    if (chatVendor === 'bedrock' &&  payload?.model?.startsWith('anthropic.claude')) {
        return {
            messages,
            anthropic_version: "bedrock-2023-05-31",
            max_tokens: 10000
        }
    } else if (chatVendor === 'bedrock' && [
            "mistral.mistral-large-2402-v1:0",
            "mistral.mixtral-8x7b-instruct-v0:1",
            "mistral.mistral-7b-instruct-v0:2"
        ].includes(payload?.model)) {
        return {
            prompt: convertMessagesToMistralPrompt(messages),
            max_tokens: 2000
        }
    } else if (chatVendor === 'bedrock' && [
            "meta.llama3-8b-instruct-v1:0",
            "meta.llama3-70b-instruct-v1:0",
            "meta.llama3-1-405b-instruct-v1:0",
            "meta.llama3-1-70b-instruct-v1:0"
        ].includes(payload?.model)) {

        return {
            prompt: convertMessagesToLlamaPrompt(messages),
            max_gen_len: 2000
        }
    } else if (chatVendor === 'localhost' && payload?.model?.startsWith('localhost.meta-llama')) {
        return {
            prompt: convertMessagesToLlamaPrompt(messages),
            max_new_tokens: 2000,
            stream: 1
        }
    } else if (chatVendor === 'openai') {
        let model = payload?.model;

        // OpenAI Aliases
        if (model === 'gpt-4-turbo') {
            model = 'gpt-4-0125-preview';
        }
        else if (model === 'gpt-3.5-turbo') {
            model = 'gpt-3.5-turbo-0125';
        }
        else if (model === 'o1') {
            model = 'o1-preview';
            if (payload?.temperature !== undefined) delete payload.temperature
            if (payload?.stream !== undefined) delete payload.stream
        }
        else if (model === 'o1-mini') {
            if (payload?.temperature !== undefined) delete payload.temperature
            if (payload?.stream !== undefined) delete payload.stream
        }


        if (accountId) payload.user = accountId
        return {
            ...payload,
            model,
            messages,
        }

    }

    // Vendor specific configurations
    const vendors = {
        'openkbs': {
            messages,
            stream: true,
            temperature: 0.01,
            max_length: 7500,
            max_new_tokens: 1000
        },
        'network': {
            messages,
            stream: true,
            temperature: 0.01,
            max_length: 7500,
            max_new_tokens: 1000
        }
    };

    return vendors[chatVendor];
};

export const getVendorRequest = ({model}) => {
    const baseRequest = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    };

    // This is how chatEndpoint should look like for localhost vendors - http://localhost:8080/pipe/meta-llama--Llama-3.1-8B-Instruct--default?stream=1
    const requests = {
        'openai': {
            ...baseRequest,
            chatEndpoint: 'https://api.openai.com/v1/chat/completions',
            headers: {
                ...baseRequest.headers,
                'Authorization': `Bearer ${process.env.OPENAI_KEY}`
            }
        },
        'openkbs': {
            ...baseRequest,
            chatEndpoint: 'https://pipe.openkbs.com/' + model,
        },
        'localhost': {
            ...baseRequest,
            chatEndpoint: (() => {
                const [_, company, ...modelParts] = model.split('.');
                const modelName = modelParts.join('.');
                return `http://localhost:8080/pipe/${company}--${modelName}--default`;
            })(),
        }
    };

    const chatVendor = model.startsWith('localhost.') ? 'localhost' : ChatModels?.[model]?.vendor;

    return requests[chatVendor];
};

const defaultInjectedRecordsLimit = 500;
export const getSearchResults = async ({payload, injectedItems, token, kbId, kbUserId}) => {
    const tokensLimit = (ChatModels[payload.model]?.searchLimit || defaultInjectedRecordsLimit) - JSON.stringify(payload.messages).length;
    const filteredInjectedItems = injectedItems ? getFiltered(injectedItems, tokensLimit) : null;
    const searchResults = filteredInjectedItems && filteredInjectedItems.length === 0
        ? {
            filtered: filteredInjectedItems,
            all: [],
            benchmarkData: {}
        }
        : await findKnn();

    return {searchResults, filteredInjectedItems}
}

export const getItemsAsString = async ({searchResults, kbId, filteredInjectedItems, AESKey, benchmarkData}) => {
    const itemIds = searchResults.filtered.map(o => o._source.itemId);

    let start = +new Date();
    const itemsData = (filteredInjectedItems && filteredInjectedItems.length)
        ? filteredInjectedItems.map(o => ({
            body: decrypt(o._source.body, AESKey),
        }))
        : await getItems(kbId, itemIds, AESKey);
    benchmarkData.getItems = +new Date()  - start;

    return itemsData.map(item => `\n\n###\n\nContent:\n${item.body}`).join('\n');
}

export const connections = {};

export function sendToAllConnections(kbId, event) {
    if (connections[kbId]) {
        for (const wsId in connections[kbId]) {
            if (connections[kbId].hasOwnProperty(wsId)) {
                const connection = connections[kbId][wsId];
                connection.ws.send(JSON.stringify(event));
            }
        }
    }
}

export const runDevServer = (handler, wsHandler) => {
    const app = express();
    app.use(express.json());

    // CORS middleware
    app.use((req, res, next) => {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
        res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');
        res.setHeader('Access-Control-Allow-Credentials', true);
        next();
    });

    // HTTP SERVER

    // Checkup route
    app.get('/checkup', (req, res) => {
        res.status(200).send({ msg: 'Server is up and running' });
    });

    app.get('/', (req, res) => {
        handler({ queryStringParameters: req.query, body: JSON.stringify(req.body) }, res);
    });

    app.post('/', (req, res) => {
        handler({ queryStringParameters: req.query, body: JSON.stringify(req.body) }, res);
    });

    // Create HTTP server
    const server = http.createServer(app);

    // WebSocket server
    const wss = new WebSocketServer({ server });

    wss.on('connection', async (ws, req) => {
        try {
            // Open new connection
            const token = url.parse(req.url, true)?.query?.token;

            const {kbUserId, myUserId, kbId} = await verifyToken(token);

            if (!kbUserId || !myUserId || !kbId) return null;

            if (!connections[kbId]) connections[kbId] = {};

            ws.kbId = kbId
            ws.wsId = generateMsgId()
            connections[kbId][ws.wsId] = { ws, kbUserId, kbId, myUserId }
        } catch (e) {
            console.log(e)
            return;
        }

        ws.on('message', (message) => {
            wsHandler(message, ws);
        });

        ws.on('close', () => {
            if (connections[ws.kbId] && connections[ws.kbId][ws.wsId]) {
                delete connections[ws.kbId][ws.wsId];
                if (Object.keys(connections[ws.kbId]).length === 0) {
                    delete connections[ws.kbId];
                }
            }
        });

        // ws.send('WebSocket connection established');
    });

    server.listen(38594, () => console.log('Server listening on port 38594'));
}
