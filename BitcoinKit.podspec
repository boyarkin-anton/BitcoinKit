Pod::Spec.new do |spec|
  spec.name = 'BitcoinKit'
  spec.version = '1.0.2'
  spec.summary = 'Bitcoin(BCH/BTC) protocol toolkit for Swift'
  spec.description = <<-DESC
                       The BitcoinKit library is a Swift implementation of the Bitcoin(BCH/BTC) protocol. This library was originally made by Katsumi Kishikawa, and now is maintained by Yenom Inc. It allows maintaining a wallet and sending/receiving transactions without needing a full blockchain node. It comes with a simple wallet app showing how to use it.
                       ```
                    DESC
  spec.homepage = 'https://github.com/yenom/BitcoinKit'
  spec.license = { :type => 'MIT', :file => 'LICENSE' }
  spec.author = { 'BitcoinKit developers' => 'usatie@yenom.tech' }

  spec.requires_arc = true
  spec.source = { git: 'https://github.com/yenom/BitcoinKit.git', tag: "v#{spec.version}" }
  spec.source_files = 'BitcoinKit/**/*.{h,m,swift}', 'Sources/BitcoinKit/**/*.{h,m,swift}'
  spec.private_header_files = 'BitcoinKit/**/BitcoinKitPrivate.h'
  spec.exclude_files = 'Sources/**/LinuxSupport.swift'
  spec.module_map = 'BitcoinKit/BitcoinKit.modulemap'
  spec.ios.deployment_target = '8.0'
  spec.swift_version = '4.1'

  spec.pod_target_xcconfig = { 'SWIFT_WHOLE_MODULE_OPTIMIZATION' => 'YES',
                               'APPLICATION_EXTENSION_API_ONLY' => 'YES',
                               'OTHER_SWIFT_FLAGS' => '-D BitcoinKitXcode' }
  spec.dependency 'secp256k1_swift', '~> 1.0.3'
  spec.dependency 'GRKOpenSSLFramework', '~> 1.0.2.15'
  spec.dependency 'GRDB.swift', '~> 3.6.2'
  spec.dependency 'GRDBCipher', '~> 3.6.2'
end
