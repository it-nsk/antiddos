import {defineConfig} from '@playwright/test';
const port=process.env.ANTIDDOS_E2E_PORT||'18082';
const origin=`http://127.0.0.1:${port}`;
const artifacts=process.env.ANTIDDOS_E2E_ARTIFACT||'../runtime/web-e2e';
export default defineConfig({testDir:'./tests',testMatch:'*.spec.ts',workers:1,timeout:30000,
 use:{baseURL:origin,viewport:{width:1440,height:1000},launchOptions:{executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome'},trace:'retain-on-failure'},
 outputDir:`${artifacts}/results`,reporter:[['list'],['html',{outputFolder:`${artifacts}/report`,open:'never'}]],
 webServer:{command:'node tests/serve.mjs',url:`${origin}/`,timeout:180000,reuseExistingServer:process.env.ANTIDDOS_E2E_REUSE==='1',env:{ANTIDDOS_E2E_PORT:port,NO_PROXY:'127.0.0.1,localhost',no_proxy:'127.0.0.1,localhost'}}
});
