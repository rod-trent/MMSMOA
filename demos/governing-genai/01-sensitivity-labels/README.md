# Demo: Creating Sensitivity Labels for AI Content
## Building a label taxonomy and enabling auto-labeling for SharePoint/Copilot

This script creates a production-ready 4-tier sensitivity label taxonomy in
Microsoft Purview and enables auto-labeling policies for SharePoint content
that Copilot will interact with.

## Prerequisites
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Running the Demo
```powershell
# Full walkthrough — creates labels interactively
.\Create-SensitivityLabels.ps1

# Preview mode — show what would be created without making changes
.\Create-SensitivityLabels.ps1 -WhatIf

# Silent mode — create everything with no prompts
.\Create-SensitivityLabels.ps1 -Force
```

## What Gets Created
| Label | Sublabels | Protection |
|-------|-----------|------------|
| Public | — | None |
| Internal | General, Project | None |
| Confidential | Standard, HR, Legal, Finance | Encryption optional |
| Highly Confidential | All Employees, Select People, Executive | Encryption enforced |

## Auto-Labeling Policy
An auto-labeling policy in simulation mode is created that will:
- Apply **Confidential/Finance** to documents containing credit card or bank account numbers
- Apply **Confidential/HR** to documents containing SSN or employee ID patterns
- Apply **Highly Confidential** to documents containing credentials or cryptographic keys

## Presenter Notes
> "Most organizations already have sensitivity labels — they're just not applied
> to enough content. Copilot uses these labels to decide what it CAN and CANNOT
> include in a summary. If a document has no label, Copilot treats it as fair game."
>
> After running the script, open the Purview portal and show the auto-labeling
> simulation results — typically 20-40% of SharePoint content gets labeled
> in the first simulation run.
