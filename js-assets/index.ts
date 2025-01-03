import * as wasm_module from './pulsebeam_core.js';
import './pulsebeam_core.d.ts';

/**
 * @pulsebeam/server: Open-Source Server SDK. Use @pulsebeam/server to generate
 * JWT (tokens) for your @pulsebeam/peer clients to use.
 * 
 * For more on @pulsebeam/server: {@link https://jsr.io/@pulsebeam/server}
 * 
 * For more on @pulsebeam/peer: {@link https://jsr.io/@pulsebeam/peer}
 * 
 * For more on PulseBeam: {@link https://pulsebeam.dev/}
 * 
 * For more on JWTs and Claims, see the RFC: {@link https://datatracker.ietf.org/doc/html/rfc7519}
 * 
 * # Example Usage
 *
 * ```ts
 * // Step 1: Initialize app
 * const { APP_ID, APP_SECRET } = process.env;
 * const app = new App(APP_ID, APP_SECRET);
 * 
 * // Step 2: Listen for JWT requests from your clients'
 * router.post('/auth', (req, res) => {
 *   // Step 3: Generate JWT and respond with JWT
 *   const claims = new PeerClaims("myGroup1", "myPeer1");
 *   const rule = new FirewallClaims("myGroup*", "*");
 *   claims.setAllowIncoming0(rule);
 *   claims.setAllowOutgoing0(rule);
 *   
 *   const ttlSeconds = 3600;
 *   const token = app.createToken(claims, ttlSeconds);
 *   res.json({ groupId, peerId, token });
 * });
 * ```
 *
 * @module
 */

/**
 * Represents the main application instance.
 * Get an app_id and app_secret from {@link https://pulsebeam.dev}
 * 
 * @example
 * const { APP_ID, APP_SECRET } = process.env;
 * const app = new App(APP_ID, APP_SECRET);
 *
 * router.post('/auth', (req, res) => {
 *   const claims = new PeerClaims("myGroup1", "myPeer1");
 *   const rule = new FirewallClaims("myGroup*", "*");
 *   claims.setAllowIncoming0(rule);
 *   claims.setAllowOutgoing0(rule);
 *
 *   const ttlSeconds = 3600; // 1 hour
 *   const token = app.createToken(claims, ttlSeconds);
 *   res.json({ groupId, peerId, token });
 * });
 */
export class App {
    private _internal: wasm_module.App
    /**
     * Creates a new App instance using your config. Essential for creating
     * client tokens.
     * Get an app_id and app_secret from {@link https://pulsebeam.dev}
     * 
     * @param {string} app_id - app_id your application ID
     * @param {string} app_secret - app_secret your application secret
     * @example const app = new App(MY_APP_ID, MY_APP_SECRET);
     */
    constructor(app_id: string, app_secret: string) {
        this._internal = new wasm_module.App(app_id, app_secret); // Keep the internal WASM instance
    }
    /**
     * Create a JWT. The JWT should be used by your client-side application.
     * To learn about JWTs and claims see JWT RFC {@link https://datatracker.ietf.org/doc/html/rfc7519}
     * @param {PeerClaims} claims - The peer claims to include in the token.
     * @param {number} durationSecs - TTL duration before token expiration
     * @return {string} JWT - The generated JWT token as a string.
     * @throws {Error} When token creation fails. Likely an issue with your
     * AppSecret.
     * @example const token = app.createToken(claims, ttlSeconds);
     */
    createToken(claims: PeerClaims, durationSecs: number): string {
        return this._internal.createToken(claims._internal, durationSecs);
    }
}


/**
 * Represents FirewallClaims for controlling network access.
 * To learn about claims see JWT RFC {@link https://datatracker.ietf.org/doc/html/rfc7519}
 * 
 */
export class FirewallClaims {
    public _internal: wasm_module.FirewallClaims
    /**
     * Creates a new FirewallClaims instance.
     * 
     * @typedef {string} Rule - Must be
     * - Is a valid UTF-8 string
     * - length(string) >= 1 character
     * - Contains no more than 1 wildcard (*)
     * 
     * Regex: /^(?:[^*]*\*[^*]*|[^*]+)$/g
     * 
     * Examples: ["*", "myGroup", "*bob", "my*"]
     *  
     * @param {Rule} group_id_rule - Desired rule for allowed groupIds
     * @param {Rule} peer_id_rule - Desired for allowed peerIds
     * @example const rule = new FirewallClaims("myGroup*", "*");
     */
    constructor(group_id_rule: string, peer_id_rule: string) {
        this._internal = new wasm_module.FirewallClaims(group_id_rule, peer_id_rule);
    }
}

/**
 * Represents peer claims for controlling access.
 * To learn about claims see JWT RFC {@link https://datatracker.ietf.org/doc/html/rfc7519}
 */
export class PeerClaims {
    public _internal: wasm_module.PeerClaims
    /**
     * Construct a new PeerClaims instance
     * 
     * Strings must be valid UTF-8 and at least 1 character
     * 
     * @param {string} group_id - Identifier for the group which the peer belongs to.
     * @param {string} peer_id - Identifier for the peer.
     * @example const claims = new PeerClaims("myGroup1", "myPeer1");
     */
    constructor(group_id: string, peer_id: string) {
        this._internal = new wasm_module.PeerClaims(group_id, peer_id);
    }

    /**
     * Configure allowlist for incoming traffic 
     * @param {FirewallClaims} claims - FirewallClaims instance representing
     * the incoming rule.
     * @example myClaims.setAllowIncoming0(myRule);
     */
    setAllowIncoming(claims: FirewallClaims) {
        this._internal.setAllowIncoming0(claims._internal);
    }

    /**
     * Configure allowlist for outgoing traffic 
     * @param {FirewallClaims} claims - FirewallClaims instance representing
     * the outgoing rule.
     * @example myClaims.setAllowOutgoing0(myRule);
     */
    setAllowOutgoing(claims: FirewallClaims) {
        this._internal.setAllowOutgoing0(claims._internal);
    }
}