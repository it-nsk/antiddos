import {defineConfig} from '@playwright/test';
const port=process.env.ANTIDDOS_E2E_PORT||'18082';
const origin=`http://127.0.0.1:${port}`;
export default defineConfig({testDir:'./tests',testMatch:'*.spec.ts',workers:1,timeout:30000,
 use:{baseURL:origin,viewport:{width:1440,height:1000},launchOptions:{executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome'},trace:'retain-on-failure'},
 outputDir:'../runtime/web-e2e/results',reporter:[['list'],['html',{outputFolder:'../runtime/web-e2e/report',open:'never'}]],
 webServer:{command:'node tests/serve.mjs',url:`${origin}/`,timeout:90000,reuseExistingServer:false,env:{ANTIDDOS_E2E_PORT:port,NO_PROXY:'127.0.0.1,localhost',no_proxy:'127.0.0.1,localhost'}}
});
