$InputFile = "TNG.000"
$ChunkSize = 500MB
$BufferSize = 4MB

if (!(Test-Path $InputFile)) {
    throw "Файл не найден: $InputFile"
}

$fs = [System.IO.File]::OpenRead($InputFile)
try {
    $buffer = New-Object byte[] $BufferSize
    $partIndex = 1

    while ($fs.Position -lt $fs.Length) {
        $partName = "{0}.part{1:D3}" -f $InputFile, $partIndex
        $remaining = $fs.Length - $fs.Position
        $targetSize = [Math]::Min($ChunkSize, $remaining)

        $out = [System.IO.File]::Create($partName)
        try {
            $written = 0L
            while ($written -lt $targetSize) {
                $toRead = [Math]::Min($BufferSize, $targetSize - $written)
                $read = $fs.Read($buffer, 0, $toRead)
                if ($read -le 0) {
                    throw "Неожиданный конец файла при записи $partName"
                }
                $out.Write($buffer, 0, $read)
                $written += $read
            }
        }
        finally {
            $out.Close()
        }

        Write-Host "Создан $partName ($targetSize bytes)"
        $partIndex++
    }
}
finally {
    $fs.Close()
}

# Хэш полного файла
Get-FileHash -Algorithm SHA256 $InputFile |
    ForEach-Object { "$($_.Hash) *$($_.Path | Split-Path -Leaf)" } |
    Set-Content -Encoding ascii "$InputFile.sha256.txt"

# Хэши частей
Get-ChildItem "$InputFile.part*" | Sort-Object Name |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash) *$($_.Path | Split-Path -Leaf)" } |
    Set-Content -Encoding ascii "$InputFile.parts.sha256.txt"

Write-Host "Готово."
Write-Host "Созданы части и файлы хэшей:"
Write-Host " - $InputFile.sha256.txt"
Write-Host " - $InputFile.parts.sha256.txt"