const express = require('express');


const {
  getUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  uploadUserImage,
  resizeImage,
  changeUserPassword,
  updateLoggedUserData,
  getLoggedUserData,
  updateLoggedUserPassword,
  deleteLoggedUserData
  

} = require('../services/userService');

const authService = require('../services/authService');

const router = express.Router();

router.use(authService.protect);

router.get('/getMe', getLoggedUserData, getUser);
router.put('/changeMyPassword', updateLoggedUserPassword);
router.put('/updateMe', updateLoggedUserData);
router.delete('/deleteMe', deleteLoggedUserData);

// Admin
router.use(authService.allowedTo('admin'));

router.put(
  '/changePassword/:id',
  changeUserPassword
);

router
  .route('/')
  .get(getUsers)
  .post(uploadUserImage, resizeImage, createUser);

router
  .route('/:id')
  .get( getUser)
  .put(uploadUserImage, resizeImage, updateUser)
  .delete( deleteUser);

module.exports = router;
