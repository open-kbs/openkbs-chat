const { execSync } = require('child_process');
const os = require('os');
const net = require('net');
const { DynamoDBClient, CreateTableCommand } = require("@aws-sdk/client-dynamodb");
const { S3Client, CreateBucketCommand, PutBucketVersioningCommand, PutBucketCorsCommand, PutBucketPolicyCommand,
    ListBucketsCommand } = require('@aws-sdk/client-s3');

const reset = "\x1b[0m";
const bold = "\x1b[1m";
const red = "\x1b[31m";
const yellow = "\x1b[33m";
const green = "\x1b[32m";

// Wrap figlet in a promise
const generateAsciiArt = async (text, figlet) => {
    return new Promise((resolve, reject) => {
        figlet(text, (err, data) => {
            if (err) {
                reject(err);
            } else {
                resolve(data);
            }
        });
    });
};

console.red = (data) =>  console.log(`${red}${data}${reset}`)
console.green = (data) =>  console.log(`${green}${bold}${data}${reset}`)
console.yellow = (data) =>  console.log(`${yellow}${bold}${data}${reset}`)

// ... (keep your console color functions and other utility functions as they are)

const CreateInfra = async (endpoint) => {
    console.log('Create local infra')

    const dynamodb = new DynamoDBClient({
        region: 'us-east-1',
        endpoint
    });

    try {
        await dynamodb.send(new CreateTableCommand({
            TableName: 'openkb-kb-chats',
            AttributeDefinitions: [
                { AttributeName: 'chatId', AttributeType: 'S' },
                { AttributeName: 'kbId', AttributeType: 'S' },
                { AttributeName: 'updatedAt', AttributeType: 'N' }
            ],
            KeySchema: [
                { AttributeName: 'kbId', KeyType: 'HASH' },
                { AttributeName: 'chatId', KeyType: 'RANGE' }
            ],
            BillingMode: 'PAY_PER_REQUEST',
            StreamSpecification: {
                StreamEnabled: true,
                StreamViewType: 'NEW_AND_OLD_IMAGES'
            },
            GlobalSecondaryIndexes: [
                {
                    IndexName: 'kbId-updatedAt-index',
                    KeySchema: [
                        { AttributeName: 'kbId', KeyType: 'HASH' },
                        { AttributeName: 'updatedAt', KeyType: 'RANGE' }
                    ],
                    Projection: {
                        ProjectionType: 'ALL'
                    }
                }
            ],
            DeletionProtectionEnabled: true
        }));
        console.green('Table created successfully!');
    } catch (error) {
        console.log('openkb-kb-chats already created')
    }

    try {
        await dynamodb.send(new CreateTableCommand({
            TableName: 'openkb-chat-messages',
            AttributeDefinitions: [
                { AttributeName: 'chatId', AttributeType: 'S' },
                { AttributeName: 'msgId', AttributeType: 'S' }
            ],
            KeySchema: [
                { AttributeName: 'chatId', KeyType: 'HASH' },
                { AttributeName: 'msgId', KeyType: 'RANGE' }
            ],
            BillingMode: 'PAY_PER_REQUEST',
            StreamSpecification: {
                StreamEnabled: true,
                StreamViewType: 'NEW_AND_OLD_IMAGES'
            },
            DeletionProtectionEnabled: true
        }));
        console.green('Table created successfully!');
    } catch (error) {
        console.log('openkb-chat-message already created')
    }

    try {
        await dynamodb.send(new CreateTableCommand({
            TableName: 'openkb-unread-messages',
            AttributeDefinitions: [
                { AttributeName: 'chatId', AttributeType: 'S' },
                { AttributeName: 'userId_kbId', AttributeType: 'S' }
            ],
            KeySchema: [
                { AttributeName: 'userId_kbId', KeyType: 'HASH' },
                { AttributeName: 'chatId', KeyType: 'RANGE' }
            ],
            BillingMode: 'PAY_PER_REQUEST',
            DeletionProtectionEnabled: true
        }));
    } catch (error) {
        console.log('openkb-unread-messages already created')
    }

    try {
        await dynamodb.send(new CreateTableCommand({
            TableName: 'openkb-kb-apikey',
            AttributeDefinitions: [
                { AttributeName: 'apiKey', AttributeType: 'S' },
                { AttributeName: 'kbId', AttributeType: 'S' }
            ],
            KeySchema: [
                { AttributeName: 'kbId', KeyType: 'HASH' },
                { AttributeName: 'apiKey', KeyType: 'RANGE' }
            ],
            BillingMode: 'PAY_PER_REQUEST',
            DeletionProtectionEnabled: true
        }));
    } catch (error) {
        console.log('openkb-kb-apikey already created')
    }


    /**
     *
     *  S 3   B U C K E T S
     *
     */

    const s3Client = new S3Client({
        region: 'us-east-1',
        endpoint: 'http://localhost:4566', // LocalStack endpoint
        forcePathStyle: true // Required for LocalStack
    });

    const bucketParams = {
        Bucket: 'openkbs-files',
        ACL: 'private' // You can set the ACL as per your requirement
    };

    const versioningParams = {
        Bucket: 'openkbs-files',
        VersioningConfiguration: {
            Status: 'Enabled'
        }
    };

    const corsParams = {
        Bucket: 'openkbs-files',
        CORSConfiguration: {
            CORSRules: [
                {
                    AllowedHeaders: ['*'],
                    AllowedMethods: ['GET', 'PUT', 'POST', 'DELETE'],
                    AllowedOrigins: ['*'],
                    ExposeHeaders: []
                }
            ]
        }
    };

    const policyParams = {
        Bucket: 'openkbs-files',
        Policy: JSON.stringify({
            Version: '2012-10-17',
            Statement: [
                {
                    Effect: 'Allow',
                    Principal: '*',
                    Action: 's3:GetObject',
                    Resource: [
                        'arn:aws:s3:::openkbs-files/files/*',
                        'arn:aws:s3:::openkbs-files/share-chat/*',
                        'arn:aws:s3:::openkbs-files/frontend/*',
                        'arn:aws:s3:::openkbs-files/download/*'
                    ]
                }
            ]
        })
    };

    try {
        // Create the bucket
        await s3Client.send(new CreateBucketCommand(bucketParams));

        // Enable versioning
        await s3Client.send(new PutBucketVersioningCommand(versioningParams));

        // Set CORS configuration
        await s3Client.send(new PutBucketCorsCommand(corsParams));

        // Set bucket policy
        await s3Client.send(new PutBucketPolicyCommand(policyParams));

        const buckets = await s3Client.send(new ListBucketsCommand({}));
        console.log('Buckets created and configured successfully')

    } catch (error) {
        console.log(error)
    }

}

function isLocalstackInstalled() {
    try {
        // Check if 'localstack' command is available
        execSync('localstack --version', { stdio: 'ignore' });
        return true;
    } catch (err) {
        return false;
    }
}

function isLocalstackRunning() {
    return new Promise((resolve) => {
        // Try connecting to the default LocalStack port
        const client = net.connect({ port: 4566 }, () => {
            client.end();
            resolve(true);
        });

        client.on('error', () => {
            resolve(false);
        });
    });
}

function printInstallationInstructions() {
    console.red('LocalStack is not installed.\n');
    console.red('Please install LocalStack by following the instructions for your operating system and try again:\n');

    const platform = os.platform();
    if (platform === 'linux') {
        console.green('**For Linux:**\n');
        console.green('```');
        console.green('curl --output localstack-cli-3.7.2-linux-amd64-onefile.tar.gz \\');
        console.green('    --location https://github.com/localstack/localstack-cli/releases/download/v3.7.2/localstack-cli-3.7.2-linux-amd64-onefile.tar.gz');
        console.green('sudo tar xvzf localstack-cli-3.7.2-linux-*-onefile.tar.gz -C /usr/local/bin');
        console.green(`sudo PERSISTENCE=1 localstack start -d`)
        console.green('```');
    } else if (platform === 'darwin') {
        console.green('**For macOS:**\n');
        console.green('```');
        console.green('brew install localstack/tap/localstack-cli');
        console.green(`sudo PERSISTENCE=1 localstack start -d`)
        console.green('```');
    } else if (platform === 'win32') {
        console.green('**For Windows:**\n');
        console.green('Please download and install from the following URL:');
        console.green('https://github.com/localstack/localstack-cli/releases/download/v3.7.2/localstack-cli-3.7.2-windows-amd64-onefile.zip');
        console.green(`sudo PERSISTENCE=1 localstack start -d`)
    } else {
        console.log('Unsupported OS. Please refer to the LocalStack installation documentation.');
    }

    console.log('\n**Note:** Some commands may require elevated permissions (e.g., `sudo`).');
}

async function main() {
    const figlet = (await import('figlet')).default;
    const chalk = (await import('chalk')).default;

    const printRunning = async () => {
        console.green('\n');
        const asciiArt = await generateAsciiArt('OpenKBS', figlet);
        console.log(chalk.blue(asciiArt));
        console.log(chalk.blue(`                             Chat Server`));
    }

    if (process.env.LOCAL_STACK_REQUIRED) {
        if (!isLocalstackInstalled()) {
            printInstallationInstructions();
            // console.log('\nContinuing without LocalStack...\n');
            process.exit(-1)
        }

        const running = await isLocalstackRunning();
        if (running) {
            await CreateInfra('http://localhost:4566');
            await printRunning();
        } else {
            console.red('LocalStack is NOT running, start it and try again.\n\n');
            console.green('sudo PERSISTENCE=1 localstack start -d')
            process.exit(-1)
        }
    } else if (process.env.AWS_REQUIRED) {
        await printRunning();
    } else if (process.env.AWS_CREATE_INFRA) {
        await CreateInfra(undefined);
    }
}

main();