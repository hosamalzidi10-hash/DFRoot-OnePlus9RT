# Исходные проекты

- **DFRoot**, diabl0w и участники: https://github.com/diabl0w/DFRoot,
  базовый commit `c274137e8c02b4f94f64d1b132d991b80c747340`. История сохранена.
  Унаследованные ссылки авторства: https://github.com/lsposed/lspromise,
  https://github.com/polygraphene/DFReroot, https://github.com/combeng6th/DirtyInit.
- **KernelSU**, tiann и участники: https://github.com/tiann/KernelSU,
  v3.3.1, commit `0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d`.
  Исходники kernel-компонента и UAPI включены в `third_party/KernelSU/`.
  Изменения порта находятся непосредственно в этих исходниках.
- **OnePlus kernel sources**: https://github.com/OnePlusOSS/android_kernel_oneplus_sm8350,
  commit и контрольная сумма закреплены в `upstream.lock.json`.
- **Android clang r383902b1**: Android Open Source Project; ссылка и SHA256
  закреплены в `upstream.lock.json`. Компилятор скачивается при сборке.

DFRoot и kernel-компонент KernelSU используют GPL-2.0; сохраняются SPDX и
copyright исходных файлов. Остальные части KernelSU имеют собственные условия
upstream; его общий LICENSE сохранён в `third_party/KernelSU/LICENSE`.
Файлы с отдельными SPDX-заголовками сохраняют указанные там лицензии.

KernelSU Manager/ksud в этом проекте не пересобираются и не переименовываются.
Пользователь отдельно устанавливает официальный KernelSU Manager v3.3.1;
DFRoot использует предоставленный им libksud.so.
