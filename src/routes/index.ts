import { Router } from 'express';
import { getHealth } from '../controllers/healthController';
import { login, getNonce } from '../controllers/authController';
import { authenticateToken } from '../middleware/auth';
import { verifyWallet, validateInstallToken } from '../controllers/authController';
import { onboardMachine, getMachine, getAllMachines, getMachineStatus, getMachineTelemetry, getMachineIdByWallet } from '../controllers/machineController';



const router = Router();
/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Check server health
 *     responses:
 *       200:
 *         description: Server is running
 */
router.get('/health', getHealth);
/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Returns JWT token
 */
router.post('/auth/login', login);
router.get('/auth/nonce', getNonce);
router.post('/auth/verify', verifyWallet);
router.post('/validate-token', validateInstallToken);
router.get("/machine-id/:address", getMachineIdByWallet);


// Example protected route
/**
 * @swagger
 * /api/protected:
 *   get:
 *     summary: Example protected route
 *     description: Returns user information if JWT token is valid
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Protected route accessed successfully
 */
router.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: (req as any).user });
});

/**
 * @swagger
 * /api/onboard:
 *   post:
 *     summary: Onboard a mining machine
 *     tags: [Machine]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               machine_id:
 *                 type: string
 *               derived_device_id:
 *                 type: string
 *               operator_wallet:
 *                 type: string
 *               operator_name:
 *                  type: string
 *               pool:
 *                 type: string
 *               actual_worker_name:
 *                 type: string
 *               worker_compliance_status:
 *                 type: string
 *               computed_status:
 *                 type: string
 *               last_heartbeat_at:
 *                 type: number
 *               metrics:
 *                 type: object
 *                 properties:
 *                   hashrate_ths:
 *                     type: number
 *                   last_share_ts:
 *                     type: number
 *                   est_earnings_24h:
 *                     type: number
 *                   pool_status_code:
 *                     type: number
 *     responses:
 *       200:
 *         description: Machine onboarded successfully
 */
//router.post('/onboard', authenticateToken, onboardMachine);
router.post('/onboard', onboardMachine);
/**
 * @swagger
 * /api/machine/{machine_id}:
 *   get:
 *     summary: Get machine details
 *     parameters:
 *       - in: path
 *         name: machine_id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Machine data
 */
router.get('/machine/:machine_id', authenticateToken, getMachine);

router.get('/machine/:machine_id/status', authenticateToken, getMachineStatus);

// Operator Routes
import { upsertOperatorProfile, getOperatorProfile } from '../controllers/operatorController';
/**
 * @swagger
 * /api/operator/profile:
 *   post:
 *     summary: Create or update operator profile
 *     tags: [Operator]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - operator_wallet
 *             properties:
 *               operator_wallet:
 *                 type: string
 *                 example: "0xabc123wallet"
 *               btc_reward_address:
 *                 type: string
 *                 example: "bc1qxyzbitcoinaddress"
 *               operator_name:
 *                  type: string
 *               pool_credentials:
 *                 type: object
 *                 properties:
 *                   pool_name:
 *                     type: string
 *                     example: "antpool"
 *                   pool_account:
 *                     type: string
 *                     example: "worker123"
 *               notifications:
 *                 type: object
 *                 properties:
 *                   email:
 *                     type: string
 *                     example: "operator@email.com"
 *                   alert_rig_offline:
 *                     type: boolean
 *                     example: true
 *                   alert_hashrate_drop:
 *                     type: boolean
 *                     example: true
 *                   alert_pool_failure:
 *                     type: boolean
 *                     example: true
 *     responses:
 *       200:
 *         description: Operator profile updated successfully
 */
router.post('/operator/profile', authenticateToken, upsertOperatorProfile);
/**
 * @swagger
 * /api/operator/{operator_wallet}:
 *   get:
 *     summary: Get operator profile
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: operator_wallet
 *         required: true
 *         schema:
 *           type: string
 *         description: Operator wallet address
 *     responses:
 *       200:
 *         description: Operator profile data
 *       404:
 *         description: Operator not found
 */
router.get('/operator/:operator_wallet', authenticateToken, getOperatorProfile);
/**
 * @swagger
 * /api/machines:
 *   get:
 *     summary: Fetch all machines
 *     description: Returns a list of all machines in the system
 *     tags: [Machines]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of machines fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   machine_id:
 *                     type: string
 *                   derived_device_id:
 *                     type: string
 *                   operator_wallet:
 *                     type: string
 *                   operator_name:
 *                     type: string
 *                   pool:
 *                     type: string
 *                   actual_worker_name:
 *                     type: string
 *                   worker_compliance_status:
 *                     type: string
 *                   computed_status:
 *                     type: string
 *                   last_heartbeat_at:
 *                     type: integer
 *                   metrics:
 *                     type: object
 *                     properties:
 *                       hashrate_ths:
 *                         type: number
 *                       last_share_ts:
 *                         type: integer
 *                       est_earnings_24h:
 *                         type: number
 *                       pool_status_code:
 *                         type: integer
 *       401:
 *         description: Unauthorized (invalid or missing token)
 *       500:
 *         description: Internal server error
 */
router.get('/machines', authenticateToken, getAllMachines);

export default router;
