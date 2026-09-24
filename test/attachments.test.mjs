import { test } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns';
import express from 'express';
import { once } from 'node:events';
import { attachmentUrl, isPublicAddress, publicLookup, downloadAttachment, decodeDocument, documentMetadata, MAX_DOCUMENT_BYTES } from '../dist/attachments.js';
import { PdfDownloads } from '../dist/downloads.js';

test('attachment addresses reject private, mapped, metadata, non-HTTPS and credential URLs', () => {
  for (const address of ['127.0.0.1', '10.2.3.4', '169.254.169.254', '100.64.1.2', '0.0.0.0', '::1', '::ffff:127.0.0.1', 'fd00::1', 'fe80::1', '2002:7f00:1::']) assert.equal(isPublicAddress(address), false, address);
  for (const address of ['8.8.8.8', '2606:4700:4700::1111']) assert.equal(isPublicAddress(address), true);
  for (const value of ['http://files.example/cv', 'file:///etc/passwd', 'sandbox:/mnt/data/cv.pdf', 'https://2130706433/x', 'https://user:pass@files.example/x', 'https://files.example:8443/x']) assert.throws(() => attachmentUrl(value));
});
test('socket lookup rejects mixed public/private answers and pins public answers', async t => {
  t.mock.method(dns, 'lookup', (_host, _options, cb) => cb(null, [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }]));
  await new Promise(resolve => publicLookup('files.example', {}, error => { assert.ok(error); resolve(); }));
  t.mock.restoreAll();
  t.mock.method(dns, 'lookup', (_host, _options, cb) => cb(null, [{ address: '8.8.8.8', family: 4 }]));
  await new Promise(resolve => publicLookup('files.example', { all: true }, (error, addresses) => { assert.equal(error, null); assert.equal(addresses[0].address, '8.8.8.8'); resolve(); }));
});
test('native attachment downloads are bounded and redirects cannot reach internal services', async () => {
  const pdf = Buffer.from('%PDF-fixture'); let calls = 0;
  const downloaded = await downloadAttachment('https://files.example/cv?signature=secret', async (_url, options) => {
    assert.equal(options.proxy, false); assert.equal(options.maxRedirects, 0); assert.equal(options.maxContentLength, MAX_DOCUMENT_BYTES);
    assert.equal(options.headers.Authorization, undefined); assert.equal(options.headers['X-API-KEY'], undefined); calls++;
    return { status: 200, headers: {}, data: pdf };
  });
  assert.deepEqual(downloaded, pdf); assert.equal(calls, 1);
  await assert.rejects(downloadAttachment('https://files.example/x', async () => ({ status: 302, headers: { location: 'https://169.254.169.254/secret' }, data: '' })), /ATTACHMENT_UNAVAILABLE/);
  await assert.rejects(downloadAttachment('https://files.example/x?signature=secret', async () => { throw new Error('signature=secret'); }), error => !error.message.includes('signature=secret'));
  await assert.rejects(downloadAttachment('https://files.example/x', async () => ({ status: 200, headers: {}, data: Buffer.alloc(MAX_DOCUMENT_BYTES + 1) })), /ATTACHMENT_UNAVAILABLE/);
});
test('document decoding handles data URIs, inferred filenames and malformed inputs', () => {
  const pdf = Buffer.from('%PDF-test');
  assert.deepEqual(decodeDocument('data:application/pdf;base64,' + pdf.toString('base64')), pdf);
  assert.equal(documentMetadata(Buffer.from([0x50, 0x4b, 3, 4])).filename, 'resume.docx');
  assert.equal(documentMetadata(Buffer.from([0x89, 0x50, 0x4e, 0x47])).filename, 'resume.png');
  assert.equal(documentMetadata(pdf, '../../cv.pdf').filename, 'cv.pdf');
  for (const invalid of ['', 'not base64', 'AAAA=', 'Zh==']) assert.throws(() => decodeDocument(invalid));
  assert.throws(() => documentMetadata(Buffer.from('<!DOCTYPE html><html>expired</html>')));
});
test('PDF links deliver original bytes and expire without leaking files', async t => {
  let now = Date.now(); const app = express(); const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  const downloads = new PdfDownloads(`http://127.0.0.1:${server.address().port}`, () => now); downloads.install(app);
  const result = downloads.publish(Buffer.from('%PDF-saved'), 'cv-مرشح.pdf'); const url = result.structuredContent.data.download_url;
  assert.equal(await (await fetch(url)).text(), '%PDF-saved');
  now += 16 * 60_000; assert.equal((await fetch(url)).status, 404);
  assert.throws(() => downloads.publish(Buffer.from('<html>failed</html>'), 'cv.pdf'), /INVALID_PDF/);
});
