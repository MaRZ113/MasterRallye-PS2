# Master Rallye PS2 TNG.000 CLI v138

Это первый release-style CLI вокруг нашего rulepack для домена `0000010c425425**`.

## Что умеет

### 1. coverage
Показывает покрытие rulepack и residual frontier.

```powershell
python master_rallye_ps2_unpacker_v138.py coverage TNG.000 master_rallye_ps2_rulepack_425425_v134.json v138_cov
```

### 2. materialize
Раскладывает matched hit'ы по rule-папкам.

```powershell
python master_rallye_ps2_unpacker_v138.py materialize TNG.000 master_rallye_ps2_rulepack_425425_v134.json v138_mat
```

С бинарниками:
```powershell
python master_rallye_ps2_unpacker_v138.py materialize TNG.000 master_rallye_ps2_rulepack_425425_v134.json v138_mat --export-binaries
```

### 3. residualize
Раскладывает residual frontier по bucket-папкам.

```powershell
python master_rallye_ps2_unpacker_v138.py residualize TNG.000 master_rallye_ps2_rulepack_425425_v134.json v138_res
```

С sample-бинарниками:
```powershell
python master_rallye_ps2_unpacker_v138.py residualize TNG.000 master_rallye_ps2_rulepack_425425_v134.json v138_res --export-samples
```

## Логика матчинга

- rule должен совпасть по `sig7`
- затем по `prev/next`
- затем по `sig8`
- затем по `body_prefix`
- для tailed-правил ещё и по `tail_sig8`

То есть правило с хвостом требует exact-tail match.

## Для чего это полезно

- `coverage` — оценить текущее покрытие rulepack
- `materialize` — получить рабочую раскладку уже известных hit'ов
- `residualize` — получить удобную очередь для следующего пополнения rulepack

## Текущее состояние rulepack

Внешний rulepack уже покрывает около 69.5% hit'ов в домене `425425**`.
Это не финальный unpacker, но уже нормальная основа для практической работы.
