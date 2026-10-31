# Differential Privacy Budgets & Action Rollback Journaling

## (Epsilon, Delta)-Differential Privacy Accounting
- Tracks cumulative privacy expenditure per tenant session.
- Halts queries once epsilon ceiling is reached to prevent membership inference and database reconstruction.

## Compensating Transaction Journal
- Records inverse compensating actions for irreversible agent side effects.
- Executes automated unwinding whenever downstream security violations occur.
