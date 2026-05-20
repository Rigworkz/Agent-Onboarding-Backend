import { Router } from 'express';
import { getHealth } from '../controllers/healthController';
import { login, getNonce } from '../controllers/authController';
import { authenticateToken } from '../middleware/auth';
import { verifyWallet, validateInstallToken } from '../controllers/authController';
import { onboardMachine, getMachine, getEncryptedAddress, getAllMachines, getMachineStatus, getMachineTelemetry, generateAndSaveFingerprint, registerMachine } from '../controllers/machineController';

import { upsertOperatorProfile, getOperatorProfile } from '../controllers/operatorController';


const router = Router();

router.get('/health', getHealth);

//router.post('/auth/login', login);
router.get('/auth/nonce', getNonce);
router.post('/auth/verify', verifyWallet);
router.post('/validate-token', validateInstallToken);

router.post("/generate-hash", authenticateToken, generateAndSaveFingerprint);
router.post("/register", registerMachine);
router.get("/encrypted-address", getEncryptedAddress);

// Example protected route

router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: (req as any).user });
});

//router.post('/onboard', authenticateToken, onboardMachine);
router.post('/onboard', onboardMachine);

router.get('/machine/:machine_id', authenticateToken, getMachine);

router.get('/machine/:machine_id/status', authenticateToken, getMachineStatus);

//operator roots

router.post('/operator/profile', authenticateToken, upsertOperatorProfile);

router.get('/operator/:operator_wallet', authenticateToken, getOperatorProfile);

router.get('/machines', authenticateToken, getAllMachines);

export default router;
