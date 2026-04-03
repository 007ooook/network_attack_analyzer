import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 读取中文语言文件
const zhLocalePath = path.join(__dirname, 'src', 'locales', 'zh.json');
const zhLocaleContent = fs.readFileSync(zhLocalePath, 'utf8');
const zhLocale = JSON.parse(zhLocaleContent);

// 读取所有 TypeScript 文件
const srcDir = path.join(__dirname, 'src');
const tsxFiles = [];

function traverse(dir) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      traverse(fullPath);
    } else if (file.endsWith('.tsx')) {
      tsxFiles.push(fullPath);
    }
  }
}

traverse(srcDir);

// 提取所有翻译键
const translationKeys = new Set();
const tRegex = /t\('([^']+)'/g;

tsxFiles.forEach(file => {
  const content = fs.readFileSync(file, 'utf8');
  let match;
  while ((match = tRegex.exec(content)) !== null) {
    translationKeys.add(match[1]);
  }
});

// 检查翻译键是否存在
const missingKeys = [];
translationKeys.forEach(key => {
  const parts = key.split('.');
  let current = zhLocale;
  let found = true;
  
  for (const part of parts) {
    if (!current || typeof current !== 'object' || !(part in current)) {
      found = false;
      break;
    }
    current = current[part];
  }
  
  if (!found) {
    missingKeys.push(key);
  }
});

// 输出结果
console.log('检查翻译键完成:');
console.log(`共检查 ${translationKeys.size} 个翻译键`);

if (missingKeys.length === 0) {
  console.log('✅ 所有翻译键都存在');
} else {
  console.log('❌ 缺少以下翻译键:');
  missingKeys.forEach(key => {
    console.log(`- ${key}`);
  });
}
