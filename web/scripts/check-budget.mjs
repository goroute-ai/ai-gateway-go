import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, '../dist');

if (!fs.existsSync(distDir)) {
  console.error(`❌ Dist directory not found at ${distDir}. Run 'npm run build' first.`);
  process.exit(1);
}

// Budget thresholds
const BUDGETS = {
  maxSingleJsUncompressed: 150 * 1024,  // 150 KB max per chunk (uncompressed)
  maxSingleJsGzip: 45 * 1024,          // 45 KB max per chunk (gzipped)
  maxCssUncompressed: 35 * 1024,        // 35 KB max CSS
  maxCssGzip: 8 * 1024,                 // 8 KB max CSS gzipped
  maxTotalDistUncompressed: 380 * 1024, // 380 KB total dist (uncompressed)
  maxTotalDistGzip: 110 * 1024,         // 110 KB total dist (gzipped across all chunks)
};

function getAllFiles(dirPath, arrayOfFiles = []) {
  const files = fs.readdirSync(dirPath);

  for (const file of files) {
    const fullPath = path.join(dirPath, file);
    if (fs.statSync(fullPath).isDirectory()) {
      getAllFiles(fullPath, arrayOfFiles);
    } else {
      arrayOfFiles.push(fullPath);
    }
  }

  return arrayOfFiles;
}

const allFiles = getAllFiles(distDir);
let totalUncompressed = 0;
let totalGzip = 0;
let hasError = false;

console.log('\n📊 Checking Production Frontend Bundle Budgets:');
console.log('────────────────────────────────────────────────────────');

for (const filePath of allFiles) {
  const relPath = path.relative(distDir, filePath);
  const buffer = fs.readFileSync(filePath);
  const uncompressedSize = buffer.length;
  const gzipSize = zlib.gzipSync(buffer).length;

  totalUncompressed += uncompressedSize;
  totalGzip += gzipSize;

  const ext = path.extname(filePath);
  const uncompressedKb = (uncompressedSize / 1024).toFixed(2);
  const gzipKb = (gzipSize / 1024).toFixed(2);

  let status = '✅ PASS';

  if (ext === '.js') {
    if (uncompressedSize > BUDGETS.maxSingleJsUncompressed || gzipSize > BUDGETS.maxSingleJsGzip) {
      status = '❌ FAIL';
      hasError = true;
    }
  } else if (ext === '.css') {
    if (uncompressedSize > BUDGETS.maxCssUncompressed || gzipSize > BUDGETS.maxCssGzip) {
      status = '❌ FAIL';
      hasError = true;
    }
  }

  console.log(
    ` ${status}  ${relPath.padEnd(35)} : ${uncompressedKb.padStart(7)} KB (gzip: ${gzipKb.padStart(6)} KB)`
  );
}

console.log('────────────────────────────────────────────────────────');
console.log(
  ` Total Bundle Size: ${(totalUncompressed / 1024).toFixed(2)} KB (gzipped: ${(totalGzip / 1024).toFixed(2)} KB)`
);

if (totalUncompressed > BUDGETS.maxTotalDistUncompressed) {
  console.error(`❌ Total bundle uncompressed size (${(totalUncompressed / 1024).toFixed(2)} KB) exceeds budget of ${(BUDGETS.maxTotalDistUncompressed / 1024).toFixed(2)} KB!`);
  hasError = true;
}

if (totalGzip > BUDGETS.maxTotalDistGzip) {
  console.error(`❌ Total bundle gzip size (${(totalGzip / 1024).toFixed(2)} KB) exceeds budget of ${(BUDGETS.maxTotalDistGzip / 1024).toFixed(2)} KB!`);
  hasError = true;
}

if (hasError) {
  console.error('\n❌ Bundle budget validation failed.');
  process.exit(1);
} else {
  console.log('\n✨ All frontend bundle budget constraints satisfied!\n');
}
