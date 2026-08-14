#include <heyaki/version.hpp>

int main() {
  const auto features = heyaki::build_info().features;
  return features.has(heyaki::BuildFeature::services) &&
                 features.has(heyaki::BuildFeature::transport_webrtc)
             ? 0
             : 1;
}

