/*
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

data "google_compute_global_address" "default" {
  name = element(concat(google_compute_global_address.default.*.name, list(var.ip_address_name)), 0)
}

resource "google_compute_global_address" "default" {
  count   = var.ip_address_name == "" ? 1 : 0
  project = var.project
  name    = "${var.name}-address"
}

resource "google_compute_global_forwarding_rule" "http" {
  project    = var.project
  name       = var.name
  target     = google_compute_target_http_proxy.default.self_link
  ip_address = data.google_compute_global_address.default.address
  port_range = "80"

  lifecycle {
    ignore_changes = [ip_address]
  }
}

resource "google_compute_global_forwarding_rule" "https" {
  project    = var.project
  count      = var.ssl ? 1 : 0
  name       = "${var.name}-https"
  target     = google_compute_target_https_proxy.default[count.index].self_link
  ip_address = data.google_compute_global_address.default.address
  port_range = "443"

  lifecycle {
    ignore_changes = [ip_address]
  }
}

# HTTP proxy when ssl is false
resource "google_compute_target_http_proxy" "default" {
  project = var.project
  name    = "${var.name}-http-proxy"
  url_map = element(compact(concat(list(var.url_map), google_compute_url_map.default.*.self_link)), 0)
}

# HTTPS proxy  when ssl is true
resource "google_compute_target_https_proxy" "default" {
  project          = var.project
  count            = var.ssl ? 1 : 0
  name             = "${var.name}-https-proxy"
  url_map          = element(compact(concat(list(var.url_map), google_compute_url_map.default.*.self_link)), 0)
  ssl_certificates = [google_compute_ssl_certificate.default[count.index].self_link]
  quic_override    = "NONE"
}

resource "google_compute_ssl_certificate" "default" {
  project     = var.project
  count       = var.ssl ? 1 : 0
  name        = join("-", compact(list(var.name, "certificate", var.cert_version)))
  private_key = var.private_key
  certificate = var.certificate

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_url_map" "default" {
  project         = var.project
  count           = var.create_url_map ? 1 : 0
  name            = "${var.name}-url-map"
  default_service = google_compute_backend_service.default.0.self_link
}

resource "google_compute_backend_service" "default" {
  project                         = var.project
  count                           = length(var.backend_params)
  name                            = "${var.name}-backend-${count.index}"
  port_name                       = element(split(",", element(var.backend_params, count.index)), 1)
  protocol                        = var.ssl ? "HTTPS" : "HTTP"
  timeout_sec                     = element(split(",", element(var.backend_params, count.index)), 3)
  security_policy                 = var.security_policy
  health_checks                   = [element(concat(google_compute_https_health_check.default.*.self_link, google_compute_http_health_check.default.*.self_link), count.index)]
  connection_draining_timeout_sec = var.connection_draining_timeout_sec

  dynamic "backend" {
    for_each = var.backends[count.index]

    content {
      group = backend.value["group"]
    }
  }
}

resource "google_compute_http_health_check" "default" {
  project            = var.project
  count              = var.ssl ? 0 : length(var.backend_params)
  name               = "${var.name}-backend-${count.index}"
  request_path       = element(split(",", element(var.backend_params, count.index)), 0)
  port               = element(split(",", element(var.backend_params, count.index)), 2)
  check_interval_sec = element(split(",", element(var.backend_params, count.index)), 4)
}

resource "google_compute_https_health_check" "default" {
  project            = var.project
  count              = var.ssl ? length(var.backend_params) : 0
  name               = "${var.name}-backend-${count.index}"
  request_path       = element(split(",", element(var.backend_params, count.index)), 0)
  port               = element(split(",", element(var.backend_params, count.index)), 2)
  check_interval_sec = element(split(",", element(var.backend_params, count.index)), 4)
}

resource "google_compute_firewall" "default-hc" {
  count         = length(var.firewall_networks)
  project       = var.project
  name          = "${var.name}-hc-${count.index}"
  network       = element(var.firewall_networks, count.index)
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"]
  target_tags   = var.target_tags

  allow {
    protocol = "tcp"
    ports    = distinct([for params in var.backend_params : element(split(",", params), 2)])
  }
}
