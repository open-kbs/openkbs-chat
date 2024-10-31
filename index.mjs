import {
    calculateTotalProperty,
    decrypt,
    hasCode,
    fetchOnRequestHandler,
    fetchOnResponseHandler,
    buildSystemContent,
    executeHandler,
    verifyToken,
    runDevServer,
    send,
    setHead,
    warmup,
    handleEmptyBody,
    handleNoMessages,
    getSearchResults,
    getItemsAsString,
    createChat,
    listChats,
    deleteChat,
    getChatMessages,
    chatAddMessages,
    chatDeleteMessage,
    updateChat,
    chatEditMessage,
    getAllUnreadMessages,
    getUnreadMessages,
    deleteUnreadMessages,
    chatMessageAddReaction,
    chatMessageRemoveReaction,
    chatStream,
    handleOnResponse,
    sha256,
    APIKeyPermissions,
    encryptMessages,
    getChat, ChatModels, createAPIKey, getAPIKeys, deleteAPIKey, loadEnv, loadChatModels
} from "./utils.mjs";
import jwt from "jsonwebtoken";
const CHAT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcERRIkiUsAMvF8n5WzZ4JUppCJGS
/u3p3yGMu1SbG2Knmu5biAC7sQk9lbGEvnWW8QwnU+GEe8dOjoDOCxchOQ==
-----END PUBLIC KEY-----`;

async function handleDefault(event, res) {
    let start = +new Date();
    if (event?.queryStringParameters?.warmup) return warmup(res)
    if (!event.body) return await handleEmptyBody(res);

    const params = JSON.parse(event.body);
    let {
        AESKey, injectedItems, token, chatPayload,
        action, title, messages, chatId, msgId, content, emojiId,
        limit, lastEvaluatedKey, predefinedAccountId, chatInstructions,
        chatIcon, chatModel, instructionSuffix, rawPrompt,
        injectedKBData, APIKeyName, apiKey, chatJWT
    } = params;

    let kbUserId = null;
    let myUserId = null;
    let kbId = null;

    try {
        if (params?.apiKey) {
            // @Todo apiKey still requires injectedKBData for On Premises instance to support requests by apiKey
            const [res] = await Promise.all([
                APIKeyPermissions(params.kbId, sha256(params.apiKey)),
            ]);

            if (res?.kbUserId && res?.permissions?.resources === '*') {
                kbId = params.kbId
                kbUserId = res?.kbUserId
                myUserId = res?.kbUserId
                AESKey = res?.AESKey;

                if (messages && AESKey) messages = encryptMessages(messages, AESKey)
            } else {
                setHead(res, 403);
                await send(res, { statusCode: 403, error: 'Insufficient API Permissions' });
                return res.end();
            }
        } else if (chatJWT) {
            const decoded = jwt.verify(chatJWT, CHAT_PUBLIC_KEY, { algorithms: ['ES256'] });
            myUserId = decoded.kbUserId;
            kbUserId = decoded.kbUserId;
            kbId = decoded?.kbId;
        } else {
            const decoded = await verifyToken(token);
            kbUserId = decoded.kbUserId
            myUserId = decoded.myUserId
            kbId = decoded.kbId
        }

        if (!kbUserId || !kbId) throw new Error('missing kbUserId or kbId');
    } catch (e) {
        setHead(res, 401);
        await send(res, {statusCode: 401, error: params?.apiKey ? 'invalid apiKey' : 'invalid JWT'});
        return res.end();
    }

    let kbDataLoadedBeforeAction = injectedKBData;

    try {
        const params = { kbId, chatId, myUserId };

        const lastMessage = messages?.[messages.length - 1];
        if (lastMessage?.content?.slice(-10)) params.content = lastMessage.content.slice(-10);
        if (lastMessage?.role) params.role = lastMessage.role;
        if (action) params.action = action;
        if (params?.apiKey) params.fromAPI = true;
    } catch (e) {}

    /**
     * Start of Actions APIs
     */
    if (action === 'createChat') {
        // ACL attribute_not_exists(chatId)
        const data = await createChat({kbId, title, messages, chatId})
        setHead(res, 200);
        await send(res, {status: 200, data});
    } else if (action === 'deleteChat') {
        // ACL deleted by {kbId, chatId}
        const data = await deleteChat({kbId, chatId})
        setHead(res, 200);
        await send(res, {status: 200, data});
    } else if (action === 'listChats') {
        // ACL listed by {kbId}
        const data = await listChats(kbId)
        setHead(res, 200);
        await send(res, {status: 200, data});
    } else if (action === 'getChat') {
        // ACL listed by {kbId}
        const data = await getChat(kbId, chatId)
        setHead(res, 200);
        await send(res, {status: 200, data});
    }
    else if (action === 'getChatMessages') {
        // ACL listed by {chatId, kbId}
        const data = await getChatMessages({chatId, kbId, myUserId, limit, lastEvaluatedKey})
        setHead(res, 200);
        await send(res, {status: 200, data});
    } else if (action === 'chatAddMessages' && chatId) {
        const data = await chatAddMessages({chatId, messages, kbId, kbDataLoadedBeforeAction})
        setHead(res, 200);
        await send(res, {status: 200, data});
    } else if (action === 'chatDeleteMessage') {
        // ACL ConditionExpression: 'kbId = :kbId'
        const data = await chatDeleteMessage({chatId, msgId, kbId})
        setHead(res, 200);
        await send(res, {status: 200, data});
    } else if (action === 'updateChat') {
        const data = await updateChat({ kbId, title, chatId, chatInstructions, chatIcon, chatModel });
        setHead(res, 200);
        await send(res, { status: 200, data });
    }
    // ACL ConditionExpression: 'kbId = :kbIdVal',
    else if (action === 'chatEditMessage') {
        const data = await chatEditMessage({ kbId, chatId, msgId, content });
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    // ACL partition key `${userId}#${kbId}`,
    else if (action === 'getAllUnreadMessages') {
        const data = await getAllUnreadMessages(myUserId, kbId);
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    // ACL partition key `${userId}#${kbId}`,
    else if (action === 'getUnreadMessages') {
        const data = await getUnreadMessages(myUserId, kbId, chatId);
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    // ACL myUserId, kbId, chatId
    else if (action === 'deleteUnreadMessages') {
        const data = await deleteUnreadMessages(myUserId, kbId, chatId);
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    // ACL myUserId, kbId, chatId
    else if (action === 'chatMessageAddReaction') {
        const data = await chatMessageAddReaction({ kbId, chatId, msgId, userId: myUserId, emojiId });
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    // ACL myUserId, kbId, chatId
    else if (action === 'chatMessageRemoveReaction') {
        const data = await chatMessageRemoveReaction({ kbId, chatId, msgId, userId: myUserId, emojiId });
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    // ACL myUserId, kbId, chatId
    else if (action === 'getOnPremisesChatModels') {
        setHead(res, 200);
        await send(res, { status: 200, data: ChatModels });
    }

    else if (action === 'createAPIKey') {
        const data = await createAPIKey(kbId, APIKeyName, APIKeyPermissions, kbUserId, myUserId, AESKey);
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    else if (action === 'getAPIKeys') {
        const data = await getAPIKeys(kbId);
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    else if (action === 'deleteAPIKey') {
        const data = await deleteAPIKey(kbId, apiKey);
        setHead(res, 200);
        await send(res, { status: 200, data });
    }

    // console.log(`${action} overhead:`, +new Date() - start)

    if (action) return res.end();
    // End of Actions APIs


    /**
     * Chat Stream API Starts Here
     */

    let payload = chatPayload;
    let benchmarkData = {};

    // Here to handle here instructions per chat

    let promises = [
        fetchOnRequestHandler(kbId),
        fetchOnResponseHandler(kbId)
    ];

    if (chatId) {
        promises.push(getChat(kbId, chatId));
    }

    let [requestHandler, responseHandler, chatData] = await Promise.all(promises);

    let kbData = injectedKBData;

    // override chat model kbData
    if (kbData?.model && payload?.model !== kbData?.model) payload.model = kbData.model

    // override chat model chatData
    if (chatData?.chatModel && payload?.model !== chatData?.chatModel) payload.model = chatData.chatModel

    // console.log('overhead: ', +new Date() - start)

    if (!kbData?.accountId || kbData?.accountId !== predefinedAccountId) throw new Error('accountId mismatch');

    if (!kbData) throw new Error('unable to get KB');

    benchmarkData.getKB = +new Date() - start;

    let decryptedKBInstructions = '';

    // append chat instructions
    if (chatData?.chatInstructions) decryptedKBInstructions = await decrypt(chatData.chatInstructions, AESKey) + '\n\n'

    decryptedKBInstructions += await decrypt(kbData.kbInstructions, AESKey);

    let count = { id: 0 };

    if (!rawPrompt && hasCode(requestHandler)) {
        const currentId = ++count.id;
        await send(res, { id: currentId, content: JSON.stringify({ _meta_type: 'EVENT_STARTED', metaEvent: 'onRequest' }), role: 'system' });

        try {
            let response = await executeHandler(requestHandler, { payload: {...payload, chatId} }, kbData, AESKey);
            const currentId = ++count.id;
            if (response?.type === 'CONTINUE') {
                await send(res, { id: currentId, content: JSON.stringify({ type: 'CONTINUE', _meta_type: "EVENT_FINISHED", _event: 'onRequest' }), role: 'system' });
            } else {
                const content = typeof response === "string"
                    ? JSON.stringify({type: "PLAIN_TEXT", data: response, _meta_type: "EVENT_FINISHED", _event: 'onRequest'})
                    : JSON.stringify({...response, _meta_type: "EVENT_FINISHED", _event: 'onRequest'})
                const currentId = ++count.id;
                await send(res, { id: currentId, content, role: 'system' });
                await send(res, { done: currentId });
                return res.end();
            }

        } catch (e) {
            const currentId = ++count.id;
            await send(res, { id: currentId, content: JSON.stringify({error: e.message, _meta_type: "EVENT_FINISHED", _event: 'onResponse'}), role: 'system' });
            await send(res, { done: currentId });
            return res.end()
        }
    }

    if (!payload.messages[0]) return handleNoMessages(res)

    let instructionSuffixString = null;

    if (instructionSuffix) {
        instructionSuffixString = instructionSuffix;
    } else {
        const {searchResults, filteredInjectedItems} = await getSearchResults({payload, injectedItems, token, kbId, kbUserId})
        benchmarkData = {...benchmarkData, ...searchResults.benchmarkData}

        if (searchResults.filtered.length) {
            instructionSuffixString = await getItemsAsString({searchResults, kbId, filteredInjectedItems, AESKey, benchmarkData})
        }
    }

    // put instructions and items to the prompt
    payload.messages = [{ role: 'system', content: buildSystemContent(decryptedKBInstructions, instructionSuffixString, kbData) }, ...payload.messages,];

    if (!rawPrompt) {
        await send(res, {
            benchmarkData: calculateTotalProperty(benchmarkData),
            userId: kbUserId,
        });
    }

    const sendMessages = [];

    try {
        await chatStream({payload, kbData},
            // on_start
            async () => {
                console.log(payload.messages?.length + ' messages sent to ' + payload?.model)
                const currentId = ++count.id; // Increment and get the current ID atomically
                await send(res, { id: currentId, content: '', role: 'assistant' });
                sendMessages.push({ id: currentId, content: '', role: 'assistant' });
                // on_delta
            }, async (data) => {
                const currentId = ++count.id; // Increment and get the current ID atomically
                await send(res, { ...data, id: currentId });
                sendMessages.push({ ...data, id: currentId });
                // on_stop
            }, async ({inputTokens, outputTokens}) => {
                if (!rawPrompt) {
                    await handleOnResponse({count, res, token, payload, sendMessages, responseHandler, kbData, AESKey, chatId})
                }
                await send(res, {done: count.id});
                res.end();
            },
            (err) => {
                console.error(err)
            }, // on_error
            () => {} // on_close
        );
    } catch (error) {
        console.error('An error occurred during the chat stream:', error);
        await send(res, { error: error.message });
        res.end();
    }
}


async function wsHandler(message, ws) {

}

(async () => {
    await loadEnv();
    await loadChatModels();
    runDevServer(handleDefault, wsHandler)
})();


