#!/bin/sh
{
  all_files=$(find / -type f 2>/dev/null | grep -E "\.(pem|cer|crt|key)$")
  skip_list="/tmp/skip_keys.txt"
  > "$skip_list"

  echo "[Public Key, Certificate(with no private key) Files]"
  for file in $all_files; do
    if [ -r "$file" ]; then
      types=$(grep '^-----BEGIN [A-Z0-9 ]\+-----$' "$file" 2>/dev/null \
        | sed 's/^-----BEGIN \(.*\)-----$/\1/' | sort -u)
      [ -z "$types" ] && continue

      if echo "$types" | grep -qE '^(PUBLIC KEY|CERTIFICATE|RSA PUBLIC KEY)$' && \
         ! echo "$types" | grep -q "PRIVATE KEY"; then
        output=$(echo "$types" | awk 'ORS=", "' | sed 's/, $//')
        printf "%-70s %s\n" "$file" "$output"
        echo "$file" >> "$skip_list"
      fi
    fi
  done

  echo
  echo "[Non-Public Key Files with MD5]"
  tmpfile="/tmp/nonpublic_md5_list.txt"
  > "$tmpfile"

  for file in $all_files; do
    grep -q "^$file$" "$skip_list" && continue

    if [ -r "$file" ]; then
      types=$(grep '^-----BEGIN [A-Z0-9 ]\+-----$' "$file" 2>/dev/null \
        | sed 's/^-----BEGIN \(.*\)-----$/\1/' | sort -u)
      [ -z "$types" ] && continue

      output=$(echo "$types" | awk 'ORS=", "' | sed 's/, $//')
      md5=$(md5sum "$file" 2>/dev/null | awk '{print $1}')
      printf "%-55s %-30s MD5: %s\n" "$file" "$output" "$md5"
      echo "$md5 $file" >> "$tmpfile"
    fi
  done

  echo
  echo "[Duplicate Files]"
  sort "$tmpfile" | cut -d ' ' -f1 | uniq -d | while read hash; do
    count=0
    grep "^$hash " "$tmpfile" | while read line; do
      filepath=$(echo "$line" | cut -d ' ' -f2-)
      printf "%-55s %s" "$filepath" "$hash"
      if [ "$count" -ne 0 ]; then
        echo " -> duplicate"
      else
        echo
      fi
      count=$((count + 1))
    done
    echo
  done

  echo "[Unique Key Files After Removing Duplicates]"

  get_key_length() {
    local file="$1"
    if grep -q "PRIVATE KEY" "$file"; then
      openssl rsa -in "$file" -text -noout 2>/dev/null | awk '/Private-Key:/ {print $2}' | sed 's/(//;s/)//'
    elif grep -q "CERTIFICATE" "$file"; then
      openssl x509 -in "$file" -text -noout 2>/dev/null | awk '/Public-Key:/ {print $2}' | sed 's/(//;s/)//'
    elif grep -q "DH PARAMETERS" "$file"; then
      openssl dhparam -in "$file" -text -noout 2>/dev/null | grep "DH Parameters:" | grep -oE '[0-9]+' | head -n1
    else
      echo "-"
    fi
  }

  get_algorithm() {
    local file="$1"
    if grep -q "RSA PRIVATE KEY" "$file"; then
      echo "RSA"
    elif grep -q "EC PRIVATE KEY" "$file"; then
      echo "ECDSA"
    elif grep -q "DSA PRIVATE KEY" "$file"; then
      echo "DSA"
    elif grep -q "DH PARAMETERS" "$file"; then
      echo "DH"
    elif grep -q "CERTIFICATE" "$file"; then
      algo=$(openssl x509 -in "$file" -text -noout 2>/dev/null | awk -F: '/Public Key Algorithm/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
      echo "${algo:-Unknown}"
    else
      echo "-"
    fi
  }

  print_file_info() {
    local file="$1"
    grep -q "^$file$" "$skip_list" && return

    if [ -r "$file" ]; then
      types=$(grep '^-----BEGIN [A-Z0-9 ]\+-----$' "$file" 2>/dev/null \
        | sed 's/^-----BEGIN \(.*\)-----$/\1/' | sort -u | awk 'ORS=", "' | sed 's/, $//')
      keylen=$(get_key_length "$file")
      algo=$(get_algorithm "$file")
      printf "%-55s %-30s %-10s %s\n" "$file" "$types" "${keylen:--} bits" "$algo"
    fi
  }

  sort "$tmpfile" | cut -d ' ' -f1 | uniq -u | while read unique_hash; do
    grep "^$unique_hash " "$tmpfile" | cut -d ' ' -f2- | while read file; do
      print_file_info "$file"
    done
  done

  sort "$tmpfile" | cut -d ' ' -f1 | uniq -d | while read dup_hash; do
    grep "^$dup_hash " "$tmpfile" | head -n 1 | cut -d ' ' -f2- | while read file; do
      print_file_info "$file"
    done
  done

  rm -f "$tmpfile" "$skip_list"
}
