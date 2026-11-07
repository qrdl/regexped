// Runs ua-parser.wasm under the FastEdge runtime (fastedge-run, through
// @gcoredev/fastedge-test) and checks every sample's answer.
//
//   npm install && npm test        (or `make test`, after `make`)
//
// Each request takes about a second locally: fastedge-run compiles the module
// for every request, which FastEdge itself does once per deployment.

import {
  defineTestSuite, runAndExit, runHttpRequest,
  assertHttpStatus, assertHttpContentType, assertHttpJson,
} from '@gcoredev/fastedge-test/test';

const named = (name, version = null) => ({ name, version });

// [User-Agent, browser, os, device, bot]
const samples = [
  ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    named('Chrome', '120.0.0.0'), named('Windows', '10'), 'desktop', null],
  ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91',
    named('Edge', '120.0.2210.91'), named('Windows', '10'), 'desktop', null],
  ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
    named('Opera', '106.0.0.0'), named('Windows', '10'), 'desktop', null],
  ['Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    named('Firefox', '121.0'), named('Linux'), 'desktop', null],
  ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    named('Safari', '17.2'), named('macOS', '10.15.7'), 'desktop', null],
  ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    named('Safari', '17.2'), named('iOS', '17.2'), 'mobile', null],
  ['Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1',
    named('Chrome', '120.0.6099.119'), named('iOS', '17.2'), 'tablet', null],
  ['Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
    named('Chrome', '120.0.6099.144'), named('Android', '14'), 'mobile', null],
  ['Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Safari/537.36',
    named('Samsung Internet', '23.0'), named('Android', '13'), 'tablet', null],
  ['Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0',
    named('Firefox', '121.0'), named('Android', '14'), 'mobile', null],
  ['Mozilla/5.0 (X11; CrOS x86_64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.235 Safari/537.36',
    named('Chrome', '120.0.6099.235'), named('ChromeOS', '15633.69.0'), 'desktop', null],
  ['Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    named('Internet Explorer', '11.0'), named('Windows', '7'), 'desktop', null],
  ['Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    named('Chrome', '120.0.6099.71'), named('Android', '6.0.1'), 'mobile', named('Googlebot', '2.1')],
  ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.6099.109 Safari/537.36',
    named('Chrome', '120.0.6099.109'), named('Windows', '10'), 'desktop', named('unidentified bot')],
  ['curl/8.4.0', null, null, 'unknown', named('curl', '8.4.0')],
  ['', null, null, 'unknown', null],
];

const check = (response, [, browser, os, device, bot]) => {
  assertHttpStatus(response, 200);
  assertHttpContentType(response, 'application/json');
  const got = assertHttpJson(response);
  const want = { browser, os, device, bot };
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    throw new Error(`got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  }
};

await runAndExit(defineTestSuite({
  wasmPath: new URL('./ua-parser.wasm', import.meta.url).pathname,
  tests: [
    ...samples.map((sample) => ({
      name: `POST → ${[sample[1]?.name ?? 'no browser', sample[2]?.name ?? 'no OS', sample[3],
        sample[4] ? `bot ${sample[4].name}` : 'not a bot'].join(', ')}`,
      async run(runner) {
        check(await runHttpRequest(runner, { path: '/', method: 'POST', body: sample[0] }), sample);
      },
    })),
    {
      name: 'GET parses the request\'s own User-Agent header',
      async run(runner) {
        const response = await runHttpRequest(runner, {
          path: '/', method: 'GET', headers: { 'user-agent': samples[1][0] },
        });
        check(response, samples[1]);
      },
    },
    {
      name: 'PUT is refused with 405',
      async run(runner) {
        assertHttpStatus(await runHttpRequest(runner, { path: '/', method: 'PUT', body: 'x' }), 405);
      },
    },
    {
      // 5,083 bytes of JSON: more than the 4,096 one blocking-write-and-flush
      // may carry, so the answer has to go out in pieces.
      name: 'an answer over 4 KB arrives whole',
      async run(runner) {
        const version = '1'.repeat(5000);
        check(await runHttpRequest(runner, { path: '/', method: 'POST', body: `Chrome/${version}` }),
          ['', named('Chrome', version), null, 'unknown', null]);
      },
    },
    {
      name: 'a body over 8 KB is refused with 413',
      async run(runner) {
        assertHttpStatus(await runHttpRequest(runner, { path: '/', method: 'POST', body: 'x'.repeat(9000) }), 413);
      },
    },
  ],
}));
