// Runs lang-detect.wasm under the FastEdge runtime (fastedge-run, through
// @gcoredev/fastedge-test) and checks every sample text's answer.
//
//   npm install && npm test        (or `make test`, after `make`)

import {
  defineTestSuite, runAndExit, runHttpRequest,
  assertHttpStatus, assertHttpContentType, assertHttpJson,
} from '@gcoredev/fastedge-test/test';

const samples = [
  ['Hello world', ['Latin']],
  ['Grüße aus Köln', ['German']],
  ['Un café, por favor', ['French', 'Spanish', 'Portuguese', 'Italian', 'Dutch',
    'Norwegian', 'Danish', 'Icelandic', 'Czech', 'Slovak', 'Hungarian']],
  ['Zażółć gęślą jaźń', ['Polish']],
  ['Příliš žluťoučký kůň', ['Czech']],
  ['Árvíztűrő tükörfúrógép', ['Hungarian']],
  ['ŠČ', ['Latvian', 'Lithuanian', 'Czech', 'Slovak', 'Slovenian', 'Croatian']],
  ['Rīga ir Latvijas galvaspilsēta', ['Latvian']],
  ['Rødgrød med fløde', ['Norwegian', 'Danish']],
  ['Привет', ['Cyrillic']],
  ['Привіт', ['Ukrainian']],
  ['Съешь', ['Russian', 'Bulgarian']],
  ['Ђорђе', ['Serbian']],
  ['Ќе', ['Macedonian']],
  ['Беларусь', ['Cyrillic']],
  ['Καλημέρα κόσμε', ['Greek']],
  ['Привет, Grüße', ['Cyrillic', 'German']],
  ['Hello Μαρία', ['Latin', 'Greek']],
  ['', []],
];

const post = (text, expected) => ({
  name: `${JSON.stringify(text)} → ${JSON.stringify(expected)}`,
  async run(runner) {
    const response = await runHttpRequest(runner, { path: '/', method: 'POST', body: text });
    assertHttpStatus(response, 200);
    assertHttpContentType(response, 'application/json');
    const got = assertHttpJson(response);
    if (JSON.stringify(got) !== JSON.stringify(expected)) {
      throw new Error(`expected ${JSON.stringify(expected)}, got ${JSON.stringify(got)}`);
    }
  },
});

await runAndExit(defineTestSuite({
  wasmPath: './lang-detect.wasm',
  tests: [
    ...samples.map(([text, expected]) => post(text, expected)),
    {
      name: 'GET → 405',
      async run(runner) {
        assertHttpStatus(await runHttpRequest(runner, { path: '/', method: 'GET' }), 405);
      },
    },
  ],
}));
