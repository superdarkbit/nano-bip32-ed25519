import { Component } from '@angular/core';

import {
  MatInputModule,
  MatSnackBar
} from '@angular/material';


import * as ed25519 from '../js/ed25519.js';
import * as bip32_ed25519 from '../js/bip32_ed25519.js';
import * as bip39 from '../js/bip39-browserified.js';
import * as nano from 'nanocurrency';

import * as nano_pow from '../js/nano-pow/startThreads.js';

@Component({
  selector: 'app-root',
  template: `
    <div style="position:fixed; z-index: 10000; width:100%; height:100%; pointer-events: none;" fxLayout="row" fxLayoutAlign="center center" *ngIf="working">
      <mat-spinner [strokeWidth]="4"></mat-spinner>
    </div>
    <div class="mat-headline">Nano BIP32-Ed25519</div>
    <div class="mat-caption">
      The purpose of this site is to display how multiple Nano addresses can be produced from a single parent public key and parent chain code with no knowledge of the parent, and counterpart, private keys. Use cases for such an ability would be the creation of watch-only wallets. This link includes other use cases: <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Use_cases">https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Use_cases</a><br>
      <br>
      This page implements the BIP32-Ed25519 specification outlined in <a href="https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view" target="_blank" style="font-style:italics;"><i>BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace</i></a>. This method involves a non-traditional signing that nonetheless produces a signature verifiable by Nano nodes.
    </div>
    <div style="overflow-wrap: break-word;word-break: break-all;">
      <div fxLayout="row wrap" fxLayoutAlign="start center" fxLayoutGap="5px">
        <mat-form-field fxFlex="1 0 auto">
          <textarea rows="3" matInput placeholder="Master seed" [(ngModel)]="properMasterSeedAsHex" [readonly]="!canManuallyEnterSeed" [disabled]="!canManuallyEnterSeed" (keyup)="onMasterSeedKey($event)"></textarea>
        </mat-form-field>
        <div fxFlex="0 0 300px" fxLayout="row wrap" fxLayoutAlign="start center" fxLayoutAlign.xs="start start">
          <mat-checkbox fxFlex="0 0 185px" [(ngModel)]="canManuallyEnterSeed" color="primary">Manually enter seed</mat-checkbox>
          <button fxFlex="0 0 300px" fxFlex.xs="1 0 100%" mat-raised-button color="basic" style="background-color: #5795f1;color: #ffffff;"
                  (click)="generateProperMasterSeed()" [disabled]="working">Generate Proper Master Seed
          </button>
        </div>
      </div>
      <div class="mat-h4">Master seeds for BIP32-Ed22519 need to be more than just random and 32-bytes. They must meet specific criteria.
        See Section V-A of <a href="https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view" target="_blank" style="font-style:italics;"><i>BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace</i></a></div>
      <div fxLayout="row wrap" fxLayoutAlign="start center" fxLayoutGap="5px">
        <mat-form-field fxFlex="1 0 auto">
          <textarea rows="3" matInput placeholder="Mnemonic representation" [(ngModel)]="properMasterSeedAsMnemonic" [readonly]="!canManuallyEnterMnemonic" [disabled]="!canManuallyEnterMnemonic" (keyup)="onMnemonicSeedKey($event)"></textarea>
        </mat-form-field>
        <div fxFlex="0 0 300px" fxLayout="row wrap" fxLayoutAlign="start center" fxLayoutAlign.xs="start start">
          <mat-checkbox fxFlex="0 0 185px" [(ngModel)]="canManuallyEnterMnemonic" color="primary">Manually enter mnemonic</mat-checkbox>
        </div>
      </div>
      <div fxLayout="row wrap" fxLayoutAlign="start center" fxLayoutGap="5px" style="">
        <mat-form-field fxFlex="1 0 auto">
          <input matInput placeholder="Derivation path" [(ngModel)]="derivationPath"/>
        </mat-form-field>
        <mat-form-field fxFlex="1 0 auto">
          <input matInput placeholder="Hashing algorithm" value="BLAKE2b" [readonly]="true" [disabled]="true"/>
        </mat-form-field>
        <button fxFlex="0 0 300px" mat-raised-button color="basic" style="background-color: #5795f1;color: #ffffff;"
                (click)="generateKeysAndOther()" [disabled]="working">Generate Keys and Other Data
        </button>
      </div>
      <div [hidden]="!parent_priv_key_hex" style="margin-top:10px;">
        <mat-card>
          <div fxLayout="row" fxLayoutAlign="center center">
            <div class="mat-h1"><span style="color: #5795f1;">address:</span> {{nano_account_addr_from_pub_child_key}}</div>
          </div>
          <div fxLayout="row wrap" fxLayoutAlign="start start" fxLayoutGap="5px">
            <div fxFlex="1 0 calc(50%-2.5px)" class="mat-h4"><strong>(Extended) Private Key:</strong><br>{{priv_child_key_hex}}</div>
            <div fxFlex="1 0 calc(50%-2.5px)" class="mat-h4"><strong>Public Key:</strong><br>{{pub_child_key_hex}}</div>
          </div>
          <div fxLayout="row wrap" fxLayoutAlign="start start" fxLayoutGap="5px">
            <div fxFlex="1 0 calc(50%-2.5px)" class="mat-h4"><strong>Parent (Extended) Private Key:</strong><br>{{parent_priv_key_hex}}
            </div>
            <div fxFlex="1 0 calc(50%-2.5px)" class="mat-h4"><strong>Parent Public Key:</strong><br>{{parent_pub_key_hex}}</div>
          </div>
          <div fxLayout="row wrap" fxLayoutAlign="start start" fxLayoutGap="5px">
            <div fxFlex="1 0 calc(50%-2.5px)" class="mat-h4"><strong>Parent Chain Code:</strong><br>{{parent_chain_code_hex}}</div>
            <div fxFlex="1 0 calc(50%-2.5px)" class="mat-h4"><i>Public child keys can be derived using the parent chain code and the parent public key. This is done with no knowledge of any of the private keys.</i></div>
          </div>
          <div>
            <span class="mat-h4" style="color: mediumseagreen;">TEST DERIVED ADDRESS:</span>
            <div>
              Do the following to test using transactions with the above Nano address (which was made from the public key above, which
              itself was generated from the parent public key and chain code with no help from any private keys):
              <ol>
                <li>Send 0.000001 Nano to the address <strong>({{nano_account_addr_from_pub_child_key}})</strong></li>
                <li>Go to <a href="http://nanode.co/account/{{nano_account_addr_from_pub_child_key}}" target="_blank">nanode.co/account/{{nano_account_addr_from_pub_child_key}}</a>
                  and copy the hash for the transaction of 0.000001 you made
                </li>
                <li>Make sure that "Open" is selected as the block type</li>
                <li>Paste the hash into the below "Associated Send Block's Hash (link)" field</li>
                <li>Click "Completely Fill Block Template" (may take a while as Proof of Work [PoW] is generated)</li>
                <li>Broadcast/process the block
                  <ul style="font-size: 11px;">
                    <li>Download and setup the Nano <strong>developer wallet</strong> if you haven't already: <a href="https://nano.org/en/wallet/">https://nano.org/en/wallet/</a></li>
                    <li>Locate the config.json file for the wallet: <a href="https://github.com/nanocurrency/raiblocks/wiki/config.json#where-is-the-configuration-file-located">https://github.com/nanocurrency/raiblocks/wiki/config.json#where-is-the-configuration-file-located</a></li>
                    <li>Open the config.json file and set "rpc_enable" to "true"</li>
                    <li>Allow the wallet to sync before opening a command line and running the cURL command below </li>
                  </ul>
                </li>
                
              </ol>
            </div>
          </div>
          <div>
            <strong>Block type:</strong>
            <mat-radio-group [(ngModel)]="type_of_the_example_block">
              <mat-radio-button value="open" style="margin-left: 10px;" color="primary">Open</mat-radio-button>
              <mat-radio-button value="send" style="margin-left: 10px;" color="primary">Send</mat-radio-button>
              <mat-radio-button value="receive" style="margin-left: 10px;" color="primary">Receive</mat-radio-button>
            </mat-radio-group>
          </div>
          <div fxLayout="row wrap" fxLayoutAlign="start center" fxLayoutGap="5px">
            <mat-form-field fxFlex="1 0 100%">
              <input matInput
                     [placeholder]="(type_of_the_example_block == 'open' || type_of_the_example_block == 'receive') ? 'Associated Send Block\\'s Hash (link)' : 'Destination Address (link)'"
                     [(ngModel)]="example_block_link"/>
            </mat-form-field>
            <mat-form-field fxFlex="1 0 49%" *ngIf="type_of_the_example_block == 'send' || type_of_the_example_block == 'receive'">
              <input matInput placeholder="Account's Current Balance" [(ngModel)]="nano_account_cur_bal"/>
              <mat-hint align="start" *ngIf="nano_account_cur_bal"><strong>{{nano_account_cur_bal}} Nano = {{nanoToRaw(nano_account_cur_bal)}} raw</strong></mat-hint>
            </mat-form-field>
            <mat-form-field fxFlex="1 0 49%" *ngIf="type_of_the_example_block == 'send' || type_of_the_example_block == 'receive'">
              <input matInput
                     [placeholder]="type_of_the_example_block == 'send' ? 'Send Amount' : (type_of_the_example_block == 'receive' ? 'Receive Amount' : '')"
                     [(ngModel)]="nano_account_amount_to_send_or_receive"/>
              <mat-hint align="start" *ngIf="nano_account_amount_to_send_or_receive"><strong>{{nano_account_amount_to_send_or_receive}} Nano = {{nanoToRaw(nano_account_amount_to_send_or_receive)}} raw</strong></mat-hint>
            </mat-form-field>
            <mat-form-field fxFlex="1 0 100%" *ngIf="type_of_the_example_block == 'open'">
              <input matInput placeholder="Resulting Balance After Open" [(ngModel)]="nano_account_amount_to_open_with"/>
              <mat-hint align="start" *ngIf="nano_account_amount_to_open_with"><strong>{{nano_account_amount_to_open_with}} Nano = {{nanoToRaw(nano_account_amount_to_open_with)}} raw</strong></mat-hint>
            </mat-form-field>
            <mat-form-field fxFlex="1 0 100%" *ngIf="type_of_the_example_block == 'send' || type_of_the_example_block == 'receive'">
              <input matInput [placeholder]="'Previous Block'" [(ngModel)]="example_block_prev"/>
            </mat-form-field>
            <button fxFlex="1 0 100%" mat-raised-button color="basic" style="background-color: #5795f1;color: #ffffff;"
                    (click)="completelyFillExampleOpenBlock()" [disabled]="working">{{!example_block_work ? 'Completely Fill' : 'Update'}} Block Template
            </button>
          </div>
          <div fxLayout="row wrap" fxLayoutAlign="start start" fxLayoutGap="5px" style="margin-top:10px;">
            <div fxFlex="1 0 100%" class="mat-h4" [hidden]="!example_block_hash">
              <strong>This Transaction's Future Hash:</strong> {{example_block_hash}}
            </div>
            <div fxFlex="1 0 100%" class="mat-h4">
              <strong>cURL command (single line):</strong><br>
              <code>
                curl -g -d '&#123;"action": "process", "block": "&#123;\\"type\\": \\"state\\",\\"account\\": \\"{{nano_account_addr_from_pub_child_key}}\\",\\"previous\\":
                \\"{{example_block_prev}}\\",\\"representative\\": \\"{{example_block_rep}}\\",\\"balance\\":
                \\"{{example_block_bal()}}\\",\\"link\\": \\"{{example_block_link ? example_block_link : 'to be filled'}}\\",\\"signature\\":
                \\"{{example_block_sig ? example_block_sig : 'to be filled'}}\\",\\"work\\":
                \\"{{example_block_work ? example_block_work : 'to be filled'}}\\"&#125;"}' [::1]:7076
              </code>
            </div>
            <div fxFlex="1 0 calc(48%-2.5px)" fxFlex.xs="100%" class="mat-h4">
              <strong>Block ({{type_of_the_example_block == 'open' ? 'an open' : (type_of_the_example_block == 'send' ? 'a send' : 'a receive') }} block):</strong>
              <pre style="overflow: auto;">
&#123;
    "type": "state",
    "account": "{{nano_account_addr_from_pub_child_key}}",
    "previous": "{{example_block_prev}}",
    "representative": "{{example_block_rep}}",
    "balance": "{{example_block_bal()}}",
    "link": "{{example_block_link ? example_block_link : 'to be filled'}}",
    "signature": "{{example_block_sig ? example_block_sig : 'to be filled'}}",
    "work": "{{example_block_work ? example_block_work : 'to be filled'}}"
&#125;
</pre>
            </div>
            <div fxFlex="1 0 calc(48%-2.5px)" fxFlex.xs="100%" class="mat-h4">
              <strong>RPC Call:</strong>
              <pre style="overflow: auto;">
&#123;
  "action": "process",
  "block": "&#123;
      "type": "state",
      "account": "{{nano_account_addr_from_pub_child_key}}",
      "previous": "{{example_block_prev}}",
      "representative": "{{example_block_rep}}",
      "balance": "{{example_block_bal()}}",
      "link": "{{example_block_link ? example_block_link : 'to be filled'}}",
      "signature": "{{example_block_sig ? example_block_sig : 'to be filled'}}",
      "work": "{{example_block_work ? example_block_work : 'to be filled'}}"
  &#125;"
&#125;
</pre>
            </div>
          </div>
        </mat-card>
      </div>
    </div>

  `,
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  public working = false;
  public canManuallyEnterSeed = false;
  public canManuallyEnterMnemonic = false;
  public properMasterSeedAsHex = '';
  public properMasterSeedAsUint8 = null;
  public properMasterSeedAsMnemonic = '';

  public derivationPath = "44'/165'/0";
  public parentPath = null;

  public chain = null;

  public parent_priv_key = null;
  public parent_priv_key_hex = null;
  public parent_priv_key_left = null;
  public parent_priv_key_left_hex = null;
  public parent_priv_key_right = null;
  public parent_priv_key_right_hex = null;
  public parent_pub_key = null;
  public parent_pub_key_hex = null;
  public parent_chain_code = null;
  public parent_chain_code_hex = null;

  public child_index = null;

  public priv_child = null
  public priv_child_key = null
  public priv_child_key_hex = null
  public priv_child_key_left = null
  public priv_child_key_left_hex = null
  public priv_child_key_right = null
  public priv_child_key_right_hex = null

  public pub_child = null
  public pub_child_key = null
  public pub_child_key_hex = null

  public nano_account_addr_from_pub_child_key = null;

  public type_of_the_example_block = "open";
  public example_block_hash = null;
  public example_block_prev = '0000000000000000000000000000000000000000000000000000000000000000';
  public example_block_rep = 'nano_1ninja7rh37ehfp9utkor5ixmxyg8kme8fnzc4zty145ibch8kf5jwpnzr3r';
  public example_block_link = null;
  public example_block_sig = null;
  public example_block_work = null;

  public nano_account_cur_bal = '0.000001';
  public nano_account_amount_to_open_with = '0.000001';
  public nano_account_amount_to_send_or_receive = '0.000001';

  constructor(
    public snackBar: MatSnackBar
  ) {
  }

  public generateProperMasterSeed() {
    this.properMasterSeedAsUint8 = bip32_ed25519.generate_proper_master_secret()
    this.properMasterSeedAsHex = bip32_ed25519.uint8ToHex(this.properMasterSeedAsUint8);
    this.properMasterSeedAsMnemonic = bip39.entropyToMnemonic(this.properMasterSeedAsHex)

    if (this.nano_account_addr_from_pub_child_key) { // Update address and keys and ofther if they were generated before
      this.generateKeysAndOther()
    }
  }

  public generateKeysAndOther() {
    if (!this.properMasterSeedAsUint8) {
      this.generateProperMasterSeed();
    }

    // Get index to deteremine which child of the parent node to obtain
    let indexOfLastSlash = this.derivationPath.lastIndexOf('/');
    this.child_index = this.derivationPath.substr(indexOfLastSlash+1, this.derivationPath.length);

    let parentPath = this.derivationPath.substr(0, indexOfLastSlash)

    if (!(this.child_index >= 0)) {
      this.snackBar.open('Error in the derivation path entered.', null, {duration: 10000});
      this.nullOutParentAndChildNodeData();
      return;
    }

    this.chain = bip32_ed25519.derive_chain(this.properMasterSeedAsUint8, parentPath)
    if (!this.chain) {
      this.snackBar.open('Bad/unsafe node generated along the derivation chain.', null, {duration: 10000});
      this.nullOutParentAndChildNodeData();
    } else {
      this.parent_priv_key = new Uint8Array(64);
      this.parent_priv_key.set(this.chain[0][0])
      this.parent_priv_key.set(this.chain[0][1], 32)
      this.parent_priv_key_hex = bip32_ed25519.uint8ToHex(this.parent_priv_key);
      this.parent_priv_key_left = this.chain[0][0]
      this.parent_priv_key_left_hex = bip32_ed25519.uint8ToHex(this.parent_priv_key_left);
      this.parent_priv_key_right = this.chain[0][1]
      this.parent_priv_key_right_hex = bip32_ed25519.uint8ToHex(this.parent_priv_key_right);
      this.parent_pub_key = this.chain[1]
      this.parent_pub_key_hex = bip32_ed25519.uint8ToHex(this.chain[1])
      this.parent_chain_code = this.chain[2]
      this.parent_chain_code_hex = bip32_ed25519.uint8ToHex(this.parent_chain_code)
    }

    if (this.chain) {
      this.priv_child = bip32_ed25519.private_child_key(this.chain, this.child_index)
      if (!this.priv_child) {
        this.snackBar.open('A bad/unsafe child node generated.', null, {duration: 10000});
        this.nullOutChildNodeData();
      } else {
        this.priv_child_key = new Uint8Array(64);
        this.priv_child_key.set(this.priv_child[0][0])
        this.priv_child_key.set(this.priv_child[0][1], 32)
        this.priv_child_key_hex = bip32_ed25519.uint8ToHex(this.priv_child_key);
        this.priv_child_key_left = this.priv_child[0][0]
        this.priv_child_key_left_hex = bip32_ed25519.uint8ToHex(this.priv_child_key_left);
        this.priv_child_key_right = this.priv_child[0][1]
        this.priv_child_key_right_hex = bip32_ed25519.uint8ToHex(this.priv_child_key_right);
        this.pub_child = bip32_ed25519.safe_public_child_key(this.chain[1], this.chain[2], this.child_index, false)
        if (!this.pub_child) {
          this.snackBar.open('A bad/unsafe child node generated.', null, {duration: 10000});
          this.nullOutChildNodeData()
        } else {
          this.pub_child_key = this.pub_child[0];
          this.pub_child_key_hex = bip32_ed25519.uint8ToHex(this.pub_child_key)
          this.nano_account_addr_from_pub_child_key = nano.deriveAddress(this.pub_child_key_hex, {useNanoPrefix: true})
        }
      }
    }

  }

  public completelyFillExampleOpenBlock() {
    let that = this;


    this.example_block_hash = nano.hashBlock({
      account: this.nano_account_addr_from_pub_child_key,
      previous: this.example_block_prev,
      representative: this.example_block_rep,
      balance: this.example_block_bal(),
      link: this.example_block_link
    });

    let example_block_hash_uint8 = bip32_ed25519.hexToUint8(this.example_block_hash)

    let example_block_sig_uint8 = bip32_ed25519.special_signing(this.priv_child_key_left, this.priv_child_key_right, this.pub_child_key, example_block_hash_uint8);

    this.example_block_sig = bip32_ed25519.uint8ToHex(example_block_sig_uint8).toUpperCase();

    this.working = true;
    let hex_to_get_work_for = this.type_of_the_example_block == 'open' ? this.pub_child_key_hex : this.example_block_prev;
    this.getWork(hex_to_get_work_for, function(work) {
      that.working = false;
      that.example_block_work = work.toUpperCase();
      that.snackBar.open('Work found!', null, {duration: 10000});
    })
  }

  public getWork(hex=null, workCallback=null) {
    let that = this;

    if (hex && localStorage.getItem(hex) && workCallback) {
      workCallback(localStorage.getItem(hex), hex);
      return;
    }

    let NUM_THREADS;

    if (self.navigator.hardwareConcurrency) {
      NUM_THREADS = self.navigator.hardwareConcurrency;
    } else {
      NUM_THREADS = 4;
    }

    let np = nano_pow;
    let workers = nano_pow.pow_initiate(NUM_THREADS, 'js/nano-pow/');

    nano_pow.pow_callback(workers, hex, function () {
    }, function (work) {
      localStorage.setItem(hex, work);
      if (workCallback) workCallback(work, hex);
    });
  }

  public onMasterSeedKey(event) {
    if (this.properMasterSeedAsHex.length == 64) {
      this.properMasterSeedAsMnemonic = bip39.entropyToMnemonic(this.properMasterSeedAsHex);
      this.properMasterSeedAsUint8 = bip32_ed25519.hexToUint8(this.properMasterSeedAsHex);
      this.generateKeysAndOther();
    } else {
      this.properMasterSeedAsMnemonic = null;
      this.properMasterSeedAsUint8 = null;
    }
  }

  public onMnemonicSeedKey(event) {
    if (this.properMasterSeedAsMnemonic.split(' ').length == 24) {
      try {
        this.properMasterSeedAsHex = bip39.mnemonicToEntropy(this.properMasterSeedAsMnemonic).toUpperCase();
        this.properMasterSeedAsUint8 = bip32_ed25519.hexToUint8(this.properMasterSeedAsHex);
        this.generateKeysAndOther();
      } catch(err) {
        console.log(err);
      }
    } else {
      this.properMasterSeedAsHex = null;
      this.properMasterSeedAsUint8 = null;
    }
  }

  public nanoToRaw(amount) {
    if (amount === 0 || amount === '0')
      return "0";
    else
      return nano.convert(amount.toString(), {from: 'Nano', to: 'raw'}).toString();
  }

  public example_block_bal() {
    if (this.type_of_the_example_block == 'open') {
      return this.nanoToRaw(parseFloat(this.nano_account_amount_to_open_with))
    } else if (this.type_of_the_example_block == 'send') {
      return this.nanoToRaw(parseFloat(this.nano_account_cur_bal) - parseFloat(this.nano_account_amount_to_send_or_receive));
    } else if (this.type_of_the_example_block == 'receive') {
      return this.nanoToRaw(parseFloat(this.nano_account_cur_bal) + parseFloat(this.nano_account_amount_to_send_or_receive));
    }
  }

  public nullOutParentAndChildNodeData() {

    this.parent_priv_key = null;
    this.parent_priv_key_hex = null;
    this.parent_priv_key_left = null;
    this.parent_priv_key_left_hex = null;
    this.parent_priv_key_right = null;
    this.parent_priv_key_right_hex = null;
    this.parent_pub_key = null;
    this.parent_pub_key_hex = null;
    this.parent_chain_code = null;
    this.parent_chain_code_hex = null;

    this.nullOutChildNodeData();
  }

  public nullOutChildNodeData() {
    this.priv_child_key = null;
    this.priv_child_key_hex = null;
    this.priv_child_key_left = null;
    this.priv_child_key_left_hex = null;
    this.priv_child_key_right = null;
    this.priv_child_key_right_hex = null;

    this.pub_child_key = null;
    this.pub_child_key_hex = null;
    this.nano_account_addr_from_pub_child_key = null;

  }
}
