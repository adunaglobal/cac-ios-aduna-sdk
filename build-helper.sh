#!/bin/sh

# Output aduna_sdk.xcframework will br located under "./build/manual/".

# ANSI color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

printf "${NC}\n-----Build Script Started-----\n\n"
printf "Cleaning build folder\n"

WORKSPACE=aduna-sdk.xcworkspace
SCHEME="Production"        
FRAMEWORK_NAME="aduna_sdk"
CONFIGURATION="Release"
OUTPUT_DIR="./build/manual/"
DEVICE_ARCHIVE="$OUTPUT_DIR/aduna-sdk-ios.xcarchive"
SIM_ARCHIVE="$OUTPUT_DIR/aduna-sdk-ios-sim.xcarchive"
XCFRAMEWORK="$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"

rm -rf ./build/manual/*
printf "${GREEN}Build folder was cleaned.${NC}\n\n"

# Run xcodebuild commands
xcodebuild archive -scheme "$SCHEME" -workspace "$WORKSPACE" -destination "generic/platform=iOS" SKIP_INSTALL=NO BUILD_LIBRARIES_FOR_DISTRIBUTION=YES -configuration "$CONFIGURATION" -archivePath "$DEVICE_ARCHIVE" && printf "${GREEN}xcodebuild for iOS succeeded.${NC}\n\n" || { printf "${RED}Error: xcodebuild for iOS failed.${NC}\n\n"; exit 1; }


# Run the second xcodebuild command
xcodebuild archive -scheme "$SCHEME" -workspace "$WORKSPACE" -destination "generic/platform=iOS Simulator" SKIP_INSTALL=NO BUILD_LIBRARIES_FOR_DISTRIBUTION=YES -configuration "$CONFIGURATION" -archivePath "$SIM_ARCHIVE" && printf "${GREEN}xcodebuild for iOS Simulator succeeded.${NC}\n\n" || { printf "${RED}Error: xcodebuild for iOS Simulator failed.${NC}\n\n"; exit 1; }

# Run the third xcodebuild command
xcodebuild -create-xcframework \
-framework Build/manual/aduna-sdk-ios.xcarchive/Products/Library/Frameworks/aduna_sdk.framework \
-framework Build/manual/aduna-sdk-ios-sim.xcarchive/Products/Library/Frameworks/aduna_sdk.framework \
-output "$XCFRAMEWORK" &&
printf "${GREEN}xcodebuild combine archs succeeded.${NC}\n\n" || { printf "${RED}Error: xcodebuild combine archs failed.${NC}\n\n"; exit 1; }

# Run the sed command to modify files
#find ./build/manual/sdk.xcframework -type f -name "sdk.h" -exec sed -i '' '/#import "sdk\/CTSubscriber_priv.h"/d' {} \; &&
#printf "${GREEN}Remove private headers succeeded.${NC}\n\n" || { printf "${RED}Error: Remove private headers failed.${NC}\n\n"; exit 1; }

# If the script reaches this point, all commands succeeded
printf "${GREEN}Build and modifications succeeded.${NC}\n\n"
printf "aduna-sdk.xcframework is now ready\n\n"
exit 0
