# MRPS2 Rulepack Tool v139

Небольшая служебная утилита для работы с внешним rulepack.

## Команды

### lint
Проверка JSON rulepack на структуру и дубликаты имён правил.

```powershell
python master_rallye_ps2_rulepack_tool_v139.py lint master_rallye_ps2_rulepack_425425_v134.json
```

### stats
Сводка по rulepack:
- by_source
- by_sig7
- by_prev_next
- by_member_count
- rule_names

```powershell
python master_rallye_ps2_rulepack_tool_v139.py stats master_rallye_ps2_rulepack_425425_v134.json v139_stats
```

### merge
Слияние новых правил в базовый rulepack по имени правила.

```powershell
python master_rallye_ps2_rulepack_tool_v139.py merge base.json additions.json merged.json
```
