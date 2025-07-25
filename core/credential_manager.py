"""
Unified credential management for all cloud providers.
"""

import dash_bootstrap_components as dbc
from dash import html
from dash_iconify import DashIconify
from typing import List, Tuple, Optional

from .credential_types import CredentialData, PROVIDER_CONFIGS, ProviderConfig
from .providers import (
    EntraCredentialProvider,
    AWSCredentialProvider,
    GCPCredentialProvider,
    AzureCredentialProvider
)


class CredentialManager:
    """Unified credential management for all cloud providers."""

    # Initialize providers
    _providers = {
        'entra': EntraCredentialProvider(),
        'aws': AWSCredentialProvider(),
        'gcp': GCPCredentialProvider(),
        'azure': AzureCredentialProvider()
    }

    @classmethod
    def get_all_credentials(cls) -> Tuple[List[Tuple[CredentialData, str, bool]], List[Tuple[CredentialData, str, bool]]]:
        """Get all credentials from all providers with classification."""
        valid_credentials = []
        expired_credentials = []

        for provider_name, provider in cls._providers.items():
            try:
                credentials = provider.get_credentials()
                for credential in credentials:
                    target_list = expired_credentials if credential.is_expired else valid_credentials
                    target_list.append((credential, provider_name, credential.is_active))
            except Exception:
                continue

        return valid_credentials, expired_credentials

    @classmethod
    def get_credentials_by_provider(cls, provider_name: str) -> List[CredentialData]:
        """Get credentials for a specific provider."""
        if provider_name not in cls._providers:
            return []

        try:
            return cls._providers[provider_name].get_credentials()
        except Exception:
            return []

    @classmethod
    def delete_credential(cls, provider_name: str, credential_id: str, credential_data: Optional[CredentialData] = None) -> str:
        """Delete a credential for a specific provider."""
        if provider_name not in cls._providers:
            return f"Unknown provider: {provider_name}"

        try:
            return cls._providers[provider_name].delete_credential(credential_id, credential_data)
        except Exception as e:
            return f"Failed to delete {provider_name} credential: {str(e)}"

    @classmethod
    def set_active_credential(cls, provider_name: str, credential_data: CredentialData) -> str:
        """Set a credential as active for a specific provider."""
        if provider_name not in cls._providers:
            return f"Unsupported provider: {provider_name}"

        try:
            return cls._providers[provider_name].set_active_credential(credential_data)
        except Exception as e:
            return f"Failed to set active credential: {str(e)}"

    @classmethod
    def create_credential_item(cls, credential_data: CredentialData, provider_name: str, is_active: bool, is_expired: bool = False) -> dbc.DropdownMenuItem:
        """Create a unified credential dropdown item."""
        name = credential_data.name[:20] if credential_data.name else 'Unknown'
        detail = credential_data.detail or ''
        config = PROVIDER_CONFIGS.get(provider_name, ProviderConfig(
            icon='mdi:key',
            color='gray',
            display_name=provider_name.upper()
        ))

        # Provider icon with appropriate color
        provider_color = 'gray' if is_expired else config.color
        provider_icon = DashIconify(icon=config.icon, className="me-2", style={"color": provider_color})

        # Status indicators
        status_elements = [provider_icon]
        if not is_expired and is_active:
            status_elements.append(DashIconify(icon="mdi:check-circle", className="text-success me-2"))
        elif is_expired:
            status_elements.append(DashIconify(icon="mdi:alert-circle", className="text-danger me-2"))

        # Name and active indicator
        name_class = "text-muted" if is_expired else ""
        name_element = html.Span(f"{provider_name.upper()}: {name}", className=name_class) if is_expired else html.Strong(f"{provider_name.upper()}: {name}")

        active_span = html.Span(" (Active)", className="text-success small" if not is_expired else "text-warning small") if is_active else None

        # Delete button
        button_type = "delete-expired-credential" if is_expired else "delete-credential"
        delete_btn = html.Button(
            [DashIconify(icon="mdi:close-circle", style={"fontSize": "18px"})],
            id={"type": button_type, "credential_id": credential_data.id, "provider": provider_name},
            className="btn btn-link text-danger p-0 border-0 ms-auto",
            style={"cursor": "pointer", "background": "none", "fontSize": "18px"},
            title="Delete credential"
        )

        # Detail text
        detail_class = "text-danger" if is_expired else "text-muted"
        detail_text = f"Expired: {detail}" if is_expired and detail else detail if detail else ("Expired" if is_expired else None)

        item_content = html.Div([
            html.Div([
                html.Div(status_elements + [name_element, active_span, html.Div([delete_btn], className="ms-auto")],
                        className="mb-1 d-flex align-items-center"),
                html.Small(detail_text, className=detail_class) if detail_text else None
            ], className="p-2")
        ], className="credential-dropdown-item-content")

        return dbc.DropdownMenuItem(item_content, className="credential-dropdown-item p-0", style={"cursor": "default"})

    @classmethod
    def get_dropdown_content(cls) -> Tuple[str, List[dbc.DropdownMenuItem]]:
        """Generate credential dropdown content and count display for all providers."""
        try:
            valid_credentials, expired_credentials = cls.get_all_credentials()

            # Build dropdown items
            dropdown_items = []

            # Add valid credentials
            for credential_data, provider_name, is_active in valid_credentials:
                item = cls.create_credential_item(credential_data, provider_name, is_active, False)
                dropdown_items.append(item)

            # Add separator if both valid and expired exist
            if valid_credentials and expired_credentials:
                dropdown_items.append(dbc.DropdownMenuItem(divider=True))

            # Add expired credentials
            for credential_data, provider_name, is_active in expired_credentials:
                item = cls.create_credential_item(credential_data, provider_name, is_active, True)
                dropdown_items.append(item)

            # Default message if no credentials
            if not dropdown_items:
                dropdown_items = [dbc.DropdownMenuItem("No credentials available", disabled=True)]

            # Create count display
            total_count = len(valid_credentials) + len(expired_credentials)
            count_text = f"{len(valid_credentials)}/{total_count}" if total_count > 0 else "0"

            return count_text, dropdown_items

        except Exception as e:
            return "Error", [dbc.DropdownMenuItem(f"Error: {str(e)}", disabled=True)]
