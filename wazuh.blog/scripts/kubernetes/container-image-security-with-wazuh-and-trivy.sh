<!-- Source: https://wazuh.com/blog/container-image-security-with-wazuh-and-trivy/ | Article: Container image security with Wazuh and Trivy -->
#!/bin/bash
# Copyright (C) 2015-2025, Wazuh Inc.

# Directory to save the custom output template
TEMPLATE_DIR="/tmp"
TEMPLATE_FILE="$TEMPLATE_DIR/trivy-custom.tmpl"

# Create the custom output template
cat <<EOL > "$TEMPLATE_FILE"
"Package","Version Installed","Vulnerability ID","Severity"
{{- range \$ri, \$r := . }}
{{- range \$vi, \$v := .Vulnerabilities }}
"{{ $v.PkgName }}","{{$v.InstalledVersion }}","{{ $v.VulnerabilityID }}","{{$v.Severity }}","{{$v.Title }}"
{{- end}}
{{- end }}
EOL

# Retrieve list of container images (including both repository and tag)
images=$(docker images --format "{{.Repository}}:{{.Tag}}")
if [ -z "$images" ]; then
  echo "No images found. Exiting..."
  exit 1
fi

# Loop through each container image and run Trivy scan
for image in $images; do
  # Run Trivy scan on the current image using the custom output template
  trivy_output=$(trivy --scanners vuln i -q --format template --template "@/tmp/trivy-custom.tmpl" "$image")

  # Check if the scan was successful
  if [ $? -ne 0 ]; then
	echo "Error running Trivy scan on image $image. Skipping..."
	continue
  fi
 
  # Process Trivy output for the current image
  while IFS= read -r line; do
	# Prepend image name with "Trivy:", followed by image name and a comma
	formatted_line="Trivy:\"$image\",$line"
	# Print the formatted line with quoted image name
	echo "$formatted_line"
  done <<< "$trivy_output"
done

# Clean up the custom output template
rm -f "$TEMPLATE_FILE"