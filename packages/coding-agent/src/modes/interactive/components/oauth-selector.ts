import type { OAuthProviderInterface } from "@mariozechner/pi-ai";
import { getOAuthProviders } from "@mariozechner/pi-ai/oauth";
import { Container, getEditorKeybindings, Spacer, TruncatedText } from "@mariozechner/pi-tui";
import type { AuthStorage } from "../../../core/auth-storage.js";
import { theme } from "../theme/theme.js";
import { DynamicBorder } from "./dynamic-border.js";

/**
 * Component that renders an OAuth provider selector
 */
export class OAuthSelectorComponent extends Container {
	private titleContainer: Container;
	private listContainer: Container;
	private allProviders: OAuthProviderInterface[] = [];
	private selectedIndex: number = 0;
	private mode: "login" | "logout";
	private authStorage: AuthStorage;
	private onSelectCallback: (providerId: string) => void;
	private onCancelCallback: () => void;
	private loginMethodParentProviderId: string | null = null;

	constructor(
		mode: "login" | "logout",
		authStorage: AuthStorage,
		onSelect: (providerId: string) => void,
		onCancel: () => void,
	) {
		super();

		this.mode = mode;
		this.authStorage = authStorage;
		this.onSelectCallback = onSelect;
		this.onCancelCallback = onCancel;

		// Load all OAuth providers
		this.loadProviders();

		// Add top border
		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));

		// Add title
		this.titleContainer = new Container();
		this.addChild(this.titleContainer);
		this.addChild(new Spacer(1));

		// Create list container
		this.listContainer = new Container();
		this.addChild(this.listContainer);

		this.addChild(new Spacer(1));

		// Add bottom border
		this.addChild(new DynamicBorder());

		// Initial render
		this.updateList();
	}

	private loadProviders(): void {
		this.allProviders = getOAuthProviders();
	}

	private getParentProvider(): OAuthProviderInterface | undefined {
		if (!this.loginMethodParentProviderId) return undefined;
		return this.allProviders.find((provider) => provider.id === this.loginMethodParentProviderId);
	}

	private getVisibleProviders(): OAuthProviderInterface[] {
		if (this.mode !== "login" || !this.loginMethodParentProviderId) {
			return this.allProviders.filter((provider) => !provider.parentProviderId);
		}

		const parentProvider = this.getParentProvider();
		if (!parentProvider) {
			return this.allProviders.filter((provider) => !provider.parentProviderId);
		}

		const alternateProviders = this.allProviders.filter(
			(provider) => provider.parentProviderId === this.loginMethodParentProviderId,
		);
		return [parentProvider, ...alternateProviders];
	}

	private getTitle(): string {
		if (this.mode === "logout") {
			return "Select provider to logout:";
		}

		const parentProvider = this.getParentProvider();
		if (parentProvider) {
			return `Select login method for ${parentProvider.name}:`;
		}

		return "Select provider to login:";
	}

	private getProviderLabel(provider: OAuthProviderInterface): string {
		if (this.mode === "login" && this.loginMethodParentProviderId) {
			return provider.loginOptionLabel ?? provider.name;
		}
		return provider.name;
	}

	private updateList(): void {
		this.titleContainer.clear();
		this.titleContainer.addChild(new TruncatedText(theme.bold(this.getTitle())));
		this.listContainer.clear();

		const visibleProviders = this.getVisibleProviders();
		if (this.selectedIndex >= visibleProviders.length) {
			this.selectedIndex = Math.max(0, visibleProviders.length - 1);
		}

		for (let i = 0; i < visibleProviders.length; i++) {
			const provider = visibleProviders[i];
			if (!provider) continue;

			const isSelected = i === this.selectedIndex;
			const showStatusIndicator = !this.loginMethodParentProviderId;
			const credentials = this.authStorage.get(provider.id);
			const isLoggedIn = credentials?.type === "oauth";
			const statusIndicator = showStatusIndicator && isLoggedIn ? theme.fg("success", " ✓ logged in") : "";
			const label = this.getProviderLabel(provider);

			let line = "";
			if (isSelected) {
				const prefix = theme.fg("accent", "→ ");
				const text = theme.fg("accent", label);
				line = prefix + text + statusIndicator;
			} else {
				line = `  ${label}${statusIndicator}`;
			}

			this.listContainer.addChild(new TruncatedText(line, 0, 0));
		}

		if (visibleProviders.length === 0) {
			const message =
				this.mode === "login" ? "No OAuth providers available" : "No OAuth providers logged in. Use /login first.";
			this.listContainer.addChild(new TruncatedText(theme.fg("muted", `  ${message}`), 0, 0));
		}
	}

	private openLoginMethodSelector(provider: OAuthProviderInterface): void {
		this.loginMethodParentProviderId = provider.id;
		this.selectedIndex = 0;
		this.updateList();
	}

	private closeLoginMethodSelector(): boolean {
		if (!this.loginMethodParentProviderId) {
			return false;
		}

		this.loginMethodParentProviderId = null;
		this.selectedIndex = 0;
		this.updateList();
		return true;
	}

	handleInput(keyData: string): void {
		const kb = getEditorKeybindings();
		const visibleProviders = this.getVisibleProviders();

		if (kb.matches(keyData, "selectUp")) {
			this.selectedIndex = Math.max(0, this.selectedIndex - 1);
			this.updateList();
		} else if (kb.matches(keyData, "selectDown")) {
			this.selectedIndex = Math.min(visibleProviders.length - 1, this.selectedIndex + 1);
			this.updateList();
		} else if (kb.matches(keyData, "selectConfirm")) {
			const selectedProvider = visibleProviders[this.selectedIndex];
			if (!selectedProvider) return;

			const hasAlternateLoginMethods =
				this.mode === "login" &&
				!this.loginMethodParentProviderId &&
				this.allProviders.some((provider) => provider.parentProviderId === selectedProvider.id);

			if (hasAlternateLoginMethods) {
				this.openLoginMethodSelector(selectedProvider);
				return;
			}

			this.onSelectCallback(selectedProvider.id);
		} else if (kb.matches(keyData, "selectCancel")) {
			if (!this.closeLoginMethodSelector()) {
				this.onCancelCallback();
			}
		}
	}
}
