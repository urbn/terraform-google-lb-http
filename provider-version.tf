terraform {
  required_providers {
    google = {
      version = var.google_provider_version
    }
    google-beta = {
      version = var.google_beta_provider_version
    }
  }
}

provider "google" {
  project = var.project
  region  = var.region
  zone    = var.zone
}

provider "google-beta" {
  project = var.project
  region  = var.region
  zone    = var.zone
}
