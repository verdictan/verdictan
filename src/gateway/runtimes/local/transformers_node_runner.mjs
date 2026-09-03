import process from 'node:process';

function readJsonFromStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8').trim();
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });
    process.stdin.on('error', reject);
  });
}

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return undefined;
}

function extractText(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .map((item) => extractText(item))
      .filter((item) => item.length > 0)
      .join('\n');
  }
  if (value && typeof value === 'object') {
    if (typeof value.text === 'string') {
      return value.text;
    }
    if (typeof value.content === 'string') {
      return value.content;
    }
    if (Array.isArray(value.content)) {
      return extractText(value.content);
    }
  }
  return '';
}

function extractPrompt(request) {
  if (Array.isArray(request.messages) && request.messages.length > 0) {
    return extractText(request.messages[request.messages.length - 1].content);
  }
  if (request.input !== undefined) {
    return extractText(request.input);
  }
  if (typeof request.prompt === 'string') {
    return request.prompt;
  }
  return '';
}

function extractEmbeddingInputs(request) {
  if (Array.isArray(request.input)) {
    return request.input.map((item) => extractText(item));
  }
  const prompt = extractPrompt(request);
  return prompt ? [prompt] : [];
}

function outputFromGenerationResult(result) {
  const rawOutput = Array.isArray(result) ? result[0]?.generated_text : result?.generated_text;
  if (typeof rawOutput === 'string') {
    return rawOutput;
  }
  if (Array.isArray(rawOutput) && rawOutput.length > 0) {
    const lastMessage = rawOutput[rawOutput.length - 1];
    return extractText(lastMessage.content ?? lastMessage);
  }
  if (rawOutput && typeof rawOutput === 'object') {
    return extractText(rawOutput);
  }
  return JSON.stringify(result);
}

function buildPipelineOptions(config) {
  const options = {};
  for (const key of ['device', 'dtype', 'cache_dir', 'revision', 'local_files_only', 'session_options']) {
    if (config[key] !== undefined) {
      options[key] = config[key];
    }
  }
  if (options.cache_dir !== undefined) {
    options.cache_dir = String(options.cache_dir);
  }
  return options;
}

function buildGenerationOptions(config, request) {
  const options = {
    max_new_tokens: firstDefined(request.max_tokens, config.max_new_tokens, config.maxNewTokens, 256),
    return_full_text: Boolean(firstDefined(config.return_full_text, config.returnFullText, false)),
  };

  const passthroughKeys = [
    ['temperature', 'temperature'],
    ['top_k', 'top_k'],
    ['top_k', 'topK'],
    ['top_p', 'top_p'],
    ['top_p', 'topP'],
    ['do_sample', 'do_sample'],
    ['do_sample', 'doSample'],
    ['repetition_penalty', 'repetition_penalty'],
    ['repetition_penalty', 'repetitionPenalty'],
    ['no_repeat_ngram_size', 'no_repeat_ngram_size'],
    ['no_repeat_ngram_size', 'noRepeatNgramSize'],
    ['num_beams', 'num_beams'],
    ['num_beams', 'numBeams'],
  ];

  for (const [targetKey, sourceKey] of passthroughKeys) {
    if (config[sourceKey] !== undefined && options[targetKey] === undefined) {
      options[targetKey] = config[sourceKey];
    }
  }

  return options;
}

function buildExtractionOptions(config) {
  return {
    pooling: firstDefined(config.pooling, 'mean'),
    normalize: firstDefined(config.normalize, true),
  };
}

function buildChatCompletion(model, text) {
  return {
    id: 'chatcmpl-transformers',
    object: 'chat.completion',
    model,
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content: text,
        },
        finish_reason: 'stop',
      },
    ],
    usage: {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    },
  };
}

function buildResponsesApi(model, text) {
  return {
    id: 'resp-transformers',
    object: 'response',
    model,
    output: [
      {
        type: 'message',
        role: 'assistant',
        content: [
          {
            type: 'output_text',
            text,
          },
        ],
      },
    ],
    usage: {
      input_tokens: 0,
      output_tokens: 0,
      total_tokens: 0,
    },
  };
}

function buildEmbeddings(model, vectors) {
  return {
    object: 'list',
    model,
    data: vectors.map((embedding, index) => ({
      object: 'embedding',
      index,
      embedding,
    })),
    usage: {
      prompt_tokens: 0,
      total_tokens: 0,
    },
  };
}

function writeChatStreamingEvents(text) {
  process.stdout.write(`data: ${JSON.stringify({
    id: 'chatcmpl-transformers',
    object: 'chat.completion.chunk',
    choices: [{ index: 0, delta: { role: 'assistant', content: text }, finish_reason: null }],
  })}\n\n`);
  process.stdout.write(`data: ${JSON.stringify({
    id: 'chatcmpl-transformers',
    object: 'chat.completion.chunk',
    choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
  })}\n\n`);
  process.stdout.write('data: [DONE]\n\n');
}

function writeResponsesStreamingEvents(text) {
  process.stdout.write(`data: ${JSON.stringify({ type: 'response.output_text.delta', delta: text })}\n\n`);
  process.stdout.write(`data: ${JSON.stringify({ type: 'response.completed' })}\n\n`);
}

async function main() {
  const payload = await readJsonFromStdin();
  const request = payload.request ?? {};
  const config = payload.execution_target?.config ?? {};
  const task = config.task;
  const model = config.model;

  if (!task || !model) {
    throw new Error('transformers runner requires execution_target.config.task and execution_target.config.model');
  }

  const { pipeline } = await import('@huggingface/transformers');
  const pipelineOptions = buildPipelineOptions(config);
  const path = String(payload.path ?? '');
  const streamRequested = Boolean(payload.stream);

  if (task === 'text-generation') {
    const generator = await pipeline('text-generation', model, pipelineOptions);
    const result = await generator(extractPrompt(request), buildGenerationOptions(config, request));
    const text = outputFromGenerationResult(result);

    if (streamRequested) {
      if (path.includes('/responses')) {
        writeResponsesStreamingEvents(text);
      } else {
        writeChatStreamingEvents(text);
      }
      return;
    }

    const response = path.includes('/responses')
      ? buildResponsesApi(model, text)
      : buildChatCompletion(model, text);
    process.stdout.write(JSON.stringify(response));
    return;
  }

  if (task === 'feature-extraction' || task === 'embeddings') {
    const extractor = await pipeline('feature-extraction', model, pipelineOptions);
    const extractionOptions = buildExtractionOptions(config);
    const prefix = typeof config.prefix === 'string' ? config.prefix : '';
    const inputs = extractEmbeddingInputs(request);
    const vectors = [];
    for (const input of inputs) {
      const result = await extractor(`${prefix}${input}`, extractionOptions);
      const data = Array.isArray(result?.data) ? result.data : Array.from(result?.data ?? []);
      vectors.push(data);
    }
    process.stdout.write(JSON.stringify(buildEmbeddings(model, vectors)));
    return;
  }

  throw new Error(`Unsupported transformers task: ${task}`);
}

main().catch((error) => {
  process.stderr.write(String(error?.stack ?? error));
  process.exit(1);
});
