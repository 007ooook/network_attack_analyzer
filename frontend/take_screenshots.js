import puppeteer from 'puppeteer';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCREENSHOT_DIR = join(__dirname, '..', 'screenshots');

if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

const APP_URL = 'http://localhost:65534';

const pages = [
  { name: 'dashboard', path: '/', title: '仪表盘' },
  { name: 'log-parser', path: '/log-parser', title: '日志解析' },
  { name: 'logs', path: '/logs', title: '日志列表' },
  { name: 'log-analysis', path: '/log-analysis', title: '日志分析' },
  { name: 'threat-intel', path: '/threat-intel', title: '威胁情报' },
  { name: 'prediction', path: '/prediction', title: '攻击预测' },
  { name: 'alerts', path: '/alerts', title: '告警管理' },
  { name: 'rules', path: '/rules', title: '规则管理' },
  { name: 'data-sources', path: '/data-sources', title: '数据源管理' },
  { name: 'data-source-logs', path: '/data-source-logs', title: '数据源日志' },
  { name: 'system-config', path: '/system-config', title: '系统配置' },
];

async function main() {
  console.log('Starting screenshot capture from real application...');
  
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1920,1080'],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });

    // Navigate to login page
    console.log('Navigating to login page...');
    await page.goto(`${APP_URL}/login`, { waitUntil: 'networkidle0' });
    await new Promise(r => setTimeout(r, 1000));

    // Login - try multiple selector strategies
    console.log('Logging in...');
    
    // Try to find username input
    const usernameInput = await page.$('input[placeholder*="用户名"]') || 
                          await page.$('input[name="username"]') || 
                          await page.$('input[type="text"]');
    if (usernameInput) {
      await usernameInput.click({ clickCount: 3 });
      await usernameInput.type('admin', { delay: 50 });
    }
    
    // Try to find password input
    const passwordInput = await page.$('input[placeholder*="密码"]') || 
                          await page.$('input[name="password"]') || 
                          await page.$('input[type="password"]');
    if (passwordInput) {
      await passwordInput.click({ clickCount: 3 });
      await passwordInput.type('admin123', { delay: 50 });
    }
    
    // Click login button - try multiple strategies
    const loginButton = await page.$('button[type="submit"]') || 
                        await page.$('.ant-btn-primary') ||
                        await page.$('button');
    if (loginButton) {
      await loginButton.click();
    } else {
      await page.keyboard.press('Enter');
    }
    
    await new Promise(r => setTimeout(r, 2000));

    // Take screenshots for each page
    for (const pageInfo of pages) {
      console.log(`Taking screenshot: ${pageInfo.title} (${pageInfo.path})`);
      
      await page.goto(`${APP_URL}${pageInfo.path}`, { waitUntil: 'networkidle0' });
      await new Promise(r => setTimeout(r, 2000));

      const screenshotPath = join(SCREENSHOT_DIR, `${pageInfo.name}.png`);
      await page.screenshot({
        path: screenshotPath,
        fullPage: false,
      });
      
      console.log(`  ✓ ${pageInfo.name}.png saved`);
    }

    console.log('\n所有截图已完成！');
  } finally {
    await browser.close();
  }
}

main().catch(console.error);
