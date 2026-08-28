#!/usr/bin/env node
// jwt_decoder.js
const { program } = require('commander');
const fs = require('fs');
const chalk = require('chalk');
const crypto = require('crypto');

class JWTDecoder {
    constructor(token, key = null) {
        this.token = token;
        this.key = key;
        this.header = null;
        this.payload = null;
        this.signature = null;
        this.validSignature = null;
        this.isExpired = null;
    }

    decode() {
        try {
            const parts = this.token.split('.');
            if (parts.length !== 3) throw new Error('Invalid JWT format');

            const header = Buffer.from(parts[0], 'base64url').toString('utf8');
            const payload = Buffer.from(parts[1], 'base64url').toString('utf8');

            this.header = JSON.parse(header);
            this.payload = JSON.parse(payload);
            this.signature = parts[2];

            // Check exp
            if (this.payload.exp) {
                const exp = new Date(this.payload.exp * 1000);
                this.isExpired = Date.now() > exp.getTime();
            }

            // Verify signature
            if (this.key) {
                this.validSignature = this.verify();
            }
        } catch (err) {
            console.error(chalk.red(`Error: ${err.message}`));
            process.exit(1);
        }
    }

    verify() {
        const parts = this.token.split('.');
        const data = `${parts[0]}.${parts[1]}`;
        const hmac = crypto.createHmac('sha256', this.key);
        hmac.update(data);
        const sig = hmac.digest('base64url');
        return sig === parts[2];
    }

    toJSON() {
        return {
            header: this.header,
            payload: this.payload,
            signature: this.signature,
            valid_signature: this.validSignature,
            expired: this.isExpired,
            token: this.token
        };
    }

    print(color = true) {
        const c = color ? chalk : { green: (s)=>s, yellow: (s)=>s, red: (s)=>s, cyan: (s)=>s };
        console.log(c.green('Header:'));
        for (const [k, v] of Object.entries(this.header)) {
            console.log(`  ${k}: ${v}`);
        }
        console.log(c.yellow('Payload:'));
        for (const [k, v] of Object.entries(this.payload)) {
            console.log(`  ${k}: ${v}`);
        }
        if (this.isExpired !== null) {
            console.log(this.isExpired ? c.red('  ✗ Token expired') : c.green('  ✓ Token valid'));
        }
        if (this.validSignature !== null) {
            console.log(this.validSignature ? c.green('  ✓ Signature verified') : c.red('  ✗ Signature invalid'));
        }
        console.log(c.cyan(`Signature: ${this.signature}`));
    }
}

program
    .argument('[token]', 'JWT token')
    .option('-k, --key <secret>', 'Secret key for HMAC')
    .option('-f, --file <path>', 'Read JWT from file')
    .option('--json', 'Output as JSON')
    .option('--color', 'Force color output')
    .parse(process.argv);

const opts = program.opts();
let token = program.args[0];

if (opts.file) {
    try {
        token = fs.readFileSync(opts.file, 'utf8').trim();
    } catch (e) {
        console.error(chalk.red(`Error reading file: ${e.message}`));
        process.exit(1);
    }
}
if (!token && !process.stdin.isTTY) {
    token = fs.readFileSync(0, 'utf8').trim();
}
if (!token) {
    console.error(chalk.red('Error: no token provided'));
    process.exit(1);
}

const decoder = new JWTDecoder(token, opts.key);
decoder.decode();

if (opts.json) {
    console.log(JSON.stringify(decoder.toJSON(), null, 2));
} else {
    decoder.print(opts.color || process.stdout.isTTY);
}
