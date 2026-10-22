# Изменения

## 4.6-op9rt.1

- Порт DFRoot 4.6 для OnePlus 9RT MT2111 с точным kernel release
  `5.4.254-qgki-gac311b3399ae`.
- Исходники и сборка обоих модулей включены в проект.
- KernelSU 3.3.1: vendor ABI/CFI, SELinux policy backend и SELinux hide для 5.4.
- Рабочие mount/umount wrappers и Individual namespace.
- In-process finit_module в bootstrap и проверка драйвера перед late-load.
- Release подпись, проверка устройства, официальный Manager и root grants
  через Manager без принудительного allow_shell.
- Документированная сборка с закреплёнными исходниками и компилятором.
- Подписанный release APK установлен и проверен на MT2111 после свежей загрузки
  22.10.2026: 19 mount-проверок и root/SELinux regression прошли без ошибок.
