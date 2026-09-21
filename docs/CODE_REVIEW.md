# Code Review

## Directory Tree
```
backend/
├── app/
│   ├── routes/
│   │   ├── static_analysis.py
│   │   └── ...
│   ├── static_analysis/
│   │   ├── apk_loader.py
│   │   ├── manifest_check.py
│   │   ├── code_analysis.py
│   │   ├── signature_check.py
│   │   ├── aggregator.py
│   │   └── ...
...
```

## Security Concerns
1. **Path Traversal / ZIP Slip**: `apk_loader.py` lacks validation against ZIP slip (e.g., extracting files outside the intended destination directory).
2. **File Size/Type Validation**: Missing strict file validation in `static_analysis.py` upload route.
3. **Hardcoded Temp Directories**: Needs secure, randomly generated subdirectories for extraction.
4. **No Execution Limits**: Missing timeouts on analysis stages (like decompilation).

## Refactoring Suggestions
1. **Move extraction logic**: Move ZIP extraction logic from `apk_loader.py` to a dedicated `apk_extractor.py` that implements safe extraction limits.
2. **Improve Error Responses**: Use a unified JSON response model in FastAPI to handle all exceptions.
3. **Unused Imports / Dead Code**: 
   - `apk_loader.py`: Redundant wrappers can be removed if Androguard works universally.
   - `aggregator.py`: Simplify logic to reduce duplicated risk addition.

## Files Needing Immediate Fixes
- `backend/app/routes/static_analysis.py`: Refactor for pipeline.
- `backend/app/static_analysis/manifest_check.py`: Add Intent/Component parsing.
- `backend/app/static_analysis/code_analysis.py`: Add Jadx decompilation.
