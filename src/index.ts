import { AuthProvider } from 'twitch';
import { BrowserWindow } from 'electron';
import * as QueryString from 'querystring';
import * as URL from 'url';

export interface TwitchClientCredentials {
	clientId: string;
	redirectURI: string;
}

export default class ElectronAuthProvider implements AuthProvider {
	private _accessToken: string = '';
	private readonly _currentScopes: Set<string> = new Set();

	constructor(private readonly _clientCredentials: TwitchClientCredentials) {
	}

	get clientId() {
		return this._clientCredentials.clientId;
	}

	get currentScopes() {
		return Array.from(this._currentScopes);
	}

	async getAccessToken(scopes?: string | string[]) {
		return new Promise<string>((resolve, reject) => {
			if (this._accessToken || !scopes) {
				resolve(this._accessToken);
				return;
			}
			if (typeof scopes === 'string') {
				scopes = [scopes];
			}
			if (scopes.every(scope => this._currentScopes.has(scope))) {
				resolve(this._accessToken);
				return;
			}

			const redir = encodeURIComponent(this._clientCredentials.redirectURI);
			const authUrl = `https://api.twitch.tv/kraken/oauth2/authorize?response_type=token&client_id=${this.clientId}&redirect_uri=${redir}&scope=${scopes.join(' ')}`;
			let done = false;

			const authWindow = new BrowserWindow({
				width: 800,
				height: 600,
				show: false,
				modal: true,
				webPreferences: {
					nodeIntegration: false
				}
			});
			authWindow.loadURL(authUrl);
			authWindow.show();

			authWindow.on('closed', () => {
				if (!done) {
					reject(new Error('window was closed'));
				}
			});

			authWindow.webContents.session.webRequest.onBeforeRequest({ urls: [this._clientCredentials.redirectURI] }, (details, callback) => {
				const url = URL.parse(details.url);
				const params = QueryString.parse(url.hash ? url.hash.substr(1) : (url.query || ''));

				if (params.error || params.access_token) {
					done = true;
					authWindow.destroy();
				}
				if (params.error) {
					reject(new Error(`Error received from Twitch: ${params.error}`));
				} else if (params.access_token) {
					this._accessToken = Array.isArray(params.access_token) ? params.access_token[0] : params.access_token;
					for (const scope of scopes!) {
						this._currentScopes.add(scope);
					}
					resolve(this._accessToken);
				}
				callback({ cancel: true });
			});
		});
	}

	setAccessToken(token: string) {
		this._accessToken = token;
	}
}
