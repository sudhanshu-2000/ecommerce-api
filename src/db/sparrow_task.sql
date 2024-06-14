-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 03, 2024 at 09:27 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `ecommerce`
--

-- --------------------------------------------------------

--
-- Table structure for table `agents_statement`
--

CREATE TABLE `agents_statement` (
  `id` int(11) NOT NULL,
  `mobile` varchar(100) NOT NULL,
  `amount` varchar(100) NOT NULL,
  `discription` varchar(100) NOT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `agents_statement`
--

INSERT INTO `agents_statement` (`id`, `mobile`, `amount`, `discription`, `date`) VALUES
(55, '8898765437', '0.14', 'Level 1', '2024-02-24 10:07:22'),
(56, '8898765437', '0.08', 'Level 1', '2024-02-24 10:07:22');

-- --------------------------------------------------------

--
-- Table structure for table `assign_module`
--

CREATE TABLE `assign_module` (
  `id` int(11) NOT NULL,
  `role` int(11) NOT NULL,
  `module` int(11) NOT NULL,
  `position` int(11) DEFAULT NULL,
  `status` varchar(1) NOT NULL DEFAULT 'Y',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `assign_module`
--

INSERT INTO `assign_module` (`id`, `role`, `module`, `position`, `status`, `date`) VALUES
(395, 6, 1, 152, 'Y', '2024-04-08 12:37:00'),
(396, 6, 13, 153, 'Y', '2024-04-08 12:37:00'),
(397, 6, 18, 154, 'Y', '2024-04-08 12:37:00'),
(398, 6, 25, 155, 'Y', '2024-04-08 12:37:00'),
(399, 6, 26, 156, 'Y', '2024-04-08 12:37:00'),
(400, 6, 33, 158, 'Y', '2024-04-08 12:37:00'),
(401, 6, 28, 157, 'Y', '2024-04-08 12:37:00'),
(402, 6, 34, 159, 'Y', '2024-04-08 12:37:00'),
(459, 3, 1, 182, 'Y', '2024-04-24 05:12:04'),
(460, 3, 18, 185, 'Y', '2024-04-24 05:12:04'),
(461, 3, 20, 184, 'Y', '2024-04-24 05:12:04'),
(462, 3, 25, 186, 'Y', '2024-04-24 05:12:04'),
(463, 3, 28, 183, 'Y', '2024-04-24 05:12:04'),
(464, 3, 26, 187, 'Y', '2024-04-24 05:12:04'),
(465, 3, 30, 188, 'Y', '2024-04-24 05:12:04'),
(466, 3, 34, 190, 'Y', '2024-04-24 05:12:04'),
(467, 3, 33, 189, 'Y', '2024-04-24 05:12:04'),
(468, 3, 35, 192, 'Y', '2024-04-24 05:12:04'),
(469, 3, 36, 193, 'Y', '2024-04-24 05:12:04'),
(470, 3, 37, 191, 'Y', '2024-04-24 05:12:04'),
(471, 5, 1, 194, 'Y', '2024-04-30 07:33:19'),
(472, 5, 13, 195, 'Y', '2024-04-30 07:33:19'),
(473, 5, 33, 202, 'Y', '2024-04-30 07:33:19'),
(474, 5, 18, 196, 'Y', '2024-04-30 07:33:19'),
(475, 5, 20, 197, 'Y', '2024-04-30 07:33:19'),
(476, 5, 25, 198, 'Y', '2024-04-30 07:33:19'),
(477, 5, 26, 199, 'Y', '2024-04-30 07:33:19'),
(478, 5, 28, 200, 'Y', '2024-04-30 07:33:19'),
(479, 5, 35, 204, 'Y', '2024-04-30 07:33:19'),
(480, 5, 30, 201, 'Y', '2024-04-30 07:33:19'),
(481, 5, 34, 203, 'Y', '2024-04-30 07:33:19'),
(482, 5, 36, 205, 'Y', '2024-04-30 07:33:19'),
(483, 5, 38, 206, 'Y', '2024-04-30 07:33:19');

-- --------------------------------------------------------

--
-- Table structure for table `assign_task`
--

CREATE TABLE `assign_task` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `task_id` int(11) NOT NULL,
  `username` varchar(100) DEFAULT NULL,
  `url` varchar(200) DEFAULT NULL,
  `status` varchar(100) NOT NULL DEFAULT 'Pending',
  `approved_declined_by` varchar(100) DEFAULT NULL,
  `expire_date` timestamp NULL DEFAULT current_timestamp(),
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `bank_details`
--

CREATE TABLE `bank_details` (
  `id` int(11) NOT NULL,
  `user_name` varchar(200) NOT NULL,
  `account_number` varchar(200) NOT NULL,
  `IFSC_code` varchar(200) NOT NULL,
  `bank_name` varchar(200) NOT NULL,
  `status` varchar(1) NOT NULL DEFAULT 'Y',
  `action` varchar(200) NOT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `buy_plan`
--

CREATE TABLE `buy_plan` (
  `id` int(11) NOT NULL,
  `user_id` varchar(100) NOT NULL,
  `plan_id` int(11) NOT NULL,
  `status` varchar(100) NOT NULL DEFAULT 'Active',
  `expire_date` datetime NOT NULL,
  `date` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `commets`
--

CREATE TABLE `commets` (
  `id` int(11) NOT NULL,
  `details` varchar(500) NOT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `commets`
--

INSERT INTO `commets` (`id`, `details`, `date`) VALUES
(1, 'Your smile is contagious.', '2024-04-11 06:02:17'),
(2, 'You are really cute.', '2024-04-11 06:02:17'),
(3, 'beautiful 😍 Cute 🥰 Lovely 🌹', '2024-04-11 06:02:17'),
(4, 'Stop being so perfect.', '2024-04-11 06:02:17'),
(5, 'Fantastically awesome.', '2024-04-11 06:02:17'),
(6, 'This looks so beautiful.', '2024-04-11 06:02:17'),
(7, 'The beauty in this picture is simply mesmerizing. It\'s a work of art.', '2024-04-11 06:02:17'),
(8, 'The colors in this picture are so vibrant and alive. It\'s like a burst of joy', '2024-04-11 06:02:17');

-- --------------------------------------------------------

--
-- Table structure for table `contact`
--

CREATE TABLE `contact` (
  `id` int(11) NOT NULL,
  `email` varchar(200) NOT NULL,
  `subject` varchar(200) NOT NULL,
  `message` varchar(300) NOT NULL,
  `image` varchar(200) DEFAULT NULL,
  `status` varchar(100) NOT NULL DEFAULT 'Pending',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `contact`
--

INSERT INTO `contact` (`id`, `email`, `subject`, `message`, `image`, `status`, `date`) VALUES
(1, 'tarun@gmail.com', 'Withdraw', 'My withdrawal is still pending', 'image-1712916729806-860214565.png', 'Pending', '2024-04-12 10:12:09'),
(2, 'tarun@gmail', 'Deposit', 'deposit pending.', 'image-1712917303444-710175830.png', 'Pending', '2024-04-12 10:21:43'),
(3, 'tarun@gmail', 'Deposit', 'deposit pending.', 'image-1712917309899-900671667.png', 'Pending', '2024-04-12 10:21:49'),
(4, 'tarun@gmail', 'Deposit', 'deposit pending.', 'image-1712917382574-247177532.png', 'Pending', '2024-04-12 10:23:02'),
(5, 'tarun@gmail', 'sdfds', 'jjjj', 'image-1712920080524-662859443.png', 'Pending', '2024-04-12 11:08:00'),
(6, 'tarun@gmail', 'Deposit', 'hii', 'image-1712985346040-123610529.png', 'Pending', '2024-04-13 05:15:46'),
(7, 'sudhamshumairua@gmail.com', 'abcd', 'Jello', NULL, 'Pending', '2024-04-13 05:21:00'),
(8, 'tarun@gmail', 'Deposit', 'hii', NULL, 'Pending', '2024-04-13 05:21:19'),
(9, 'tejpal@frensysinfotech.com', 'Deposit', 'Pending h mera deposit', NULL, 'Pending', '2024-04-30 11:11:11');

-- --------------------------------------------------------

--
-- Table structure for table `deposit`
--

CREATE TABLE `deposit` (
  `id` int(11) NOT NULL,
  `user_name` varchar(200) NOT NULL,
  `balance` varchar(200) NOT NULL,
  `image` varchar(200) DEFAULT NULL,
  `image_path` varchar(250) DEFAULT NULL,
  `transaction_id` varchar(50) DEFAULT NULL,
  `payment_type` varchar(50) NOT NULL,
  `upi_id` varchar(100) DEFAULT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'Pending',
  `reason` varchar(45) DEFAULT NULL,
  `Approved_declined_By` varchar(50) NOT NULL DEFAULT 'Not Approved',
  `paymethod_id` int(11) DEFAULT NULL,
  `coupan` varchar(100) DEFAULT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `level`
--

CREATE TABLE `level` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `price` varchar(100) NOT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `level`
--

INSERT INTO `level` (`id`, `name`, `price`, `date`) VALUES
(4, '1', '30', '2024-04-30 09:40:54'),
(5, '2', '20', '2024-04-30 09:41:04'),
(6, '3', '10', '2024-04-30 09:41:18');

-- --------------------------------------------------------

--
-- Table structure for table `login`
--

CREATE TABLE `login` (
  `id` int(11) NOT NULL,
  `name` varchar(10) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `is_active` varchar(1) NOT NULL DEFAULT 'N',
  `status` varchar(1) NOT NULL DEFAULT 'Y',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `login`
--

INSERT INTO `login` (`id`, `name`, `username`, `password`, `is_active`, `status`, `date`) VALUES
(14, 'Kumar Ji', 'Superadmin', '$2b$12$JZZL/FuFOD.ibnxlComhVuWe7YzDq1zswgezphrzLk.Auq1wLuqGW', 'N', 'Y', '2022-07-29 00:02:44'),
(15, 'testing', 'test', '$2b$10$mh/WZV1LwVEnxzoTa5rKiuUOZT2urb81itGLIV73yiJ/rAgmwSHDi', 'N', 'Y', '2023-03-03 06:05:15'),
(16, 'tehss', 'jsdhdfs', '$2b$10$M0LQPLeaHOuD2WAhadVhEOPquvsA08DZZhb/erVO1GDfBb4mQ9/b6', 'N', 'Y', '2024-04-16 07:37:27');

-- --------------------------------------------------------

--
-- Table structure for table `module`
--

CREATE TABLE `module` (
  `id` int(11) NOT NULL,
  `module_name` varchar(200) NOT NULL,
  `url` varchar(200) NOT NULL,
  `status` varchar(1) NOT NULL DEFAULT 'Y',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `module`
--

INSERT INTO `module` (`id`, `module_name`, `url`, `status`, `date`) VALUES
(1, 'Dashboard', '/home/dashboard', 'Y', '2022-07-26 05:55:10'),
(13, 'module', '/home/module', 'Y', '2022-07-26 05:55:10'),
(18, 'role', '/home/role', 'Y', '2022-08-03 00:44:23'),
(20, 'activity mapping', '/home/activity-mapping', 'Y', '2022-08-05 00:35:20'),
(25, 'Withdrawal', '/home/withdrawal', 'Y', '2022-10-10 11:56:54'),
(26, 'Deposit', '/home/deposit', 'Y', '2022-10-10 11:57:34'),
(28, 'User Details', '/home/user-details', 'Y', '2022-10-19 05:26:14'),
(30, 'Sub-Admin', '/home/sub-admin', 'Y', '2023-02-16 09:55:26'),
(33, 'Bonus-tables', '/home/bonus-tables', 'Y', '2023-10-02 11:44:42'),
(34, 'Platform', '/home/platform', 'Y', '2024-04-08 11:27:31'),
(35, 'Task', '/home/task', 'Y', '2024-04-08 12:31:15'),
(36, 'Assign-Task', '/home/assign-task', 'Y', '2024-04-12 06:29:59'),
(37, 'Plan', '/home/plan', 'Y', '2024-04-24 05:11:49'),
(38, 'Level and Price', '/home/level-price', 'Y', '2024-04-30 07:33:08');

-- --------------------------------------------------------

--
-- Table structure for table `new_payment_details`
--

CREATE TABLE `new_payment_details` (
  `id` int(11) NOT NULL,
  `upi_id` varchar(100) NOT NULL,
  `qr_code` varchar(100) NOT NULL,
  `number` varchar(10) NOT NULL,
  `status` varchar(1) NOT NULL DEFAULT 'N',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `new_payment_details`
--

INSERT INTO `new_payment_details` (`id`, `upi_id`, `qr_code`, `number`, `status`, `date`) VALUES
(1, '999999999@upi', 'https://sparrowsports.com/image/task_deposit.png', '999999999', 'Y', '2024-04-06 04:51:38');

-- --------------------------------------------------------

--
-- Table structure for table `otp`
--

CREATE TABLE `otp` (
  `id` int(11) NOT NULL,
  `otp` varchar(200) NOT NULL,
  `number` varchar(200) NOT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `payment_bonus`
--

CREATE TABLE `payment_bonus` (
  `id` int(11) NOT NULL,
  `offer_name` varchar(100) NOT NULL,
  `amount_start` varchar(100) NOT NULL,
  `amount_end` varchar(100) NOT NULL,
  `percentage` varchar(50) NOT NULL,
  `times` varchar(100) NOT NULL,
  `status` varchar(1) NOT NULL DEFAULT 'N',
  `end_date` date NOT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `payment_bonus`
--

INSERT INTO `payment_bonus` (`id`, `offer_name`, `amount_start`, `amount_end`, `percentage`, `times`, `status`, `end_date`, `date`) VALUES
(4, 'First', '200', '500000', '50', '1', 'Y', '2050-12-31', '2024-02-24 10:31:34'),
(5, 'Second', '200', '500000', '30', '1', 'Y', '2050-12-31', '2024-02-24 10:32:41'),
(6, 'third', '200', '500000', '20', '1', 'Y', '2050-12-31', '2024-02-24 10:33:13'),
(7, 'fourth', '200', '500000', '10', '1', 'Y', '2050-12-31', '2024-02-24 10:33:38'),
(8, 'fifth', '200', '500000', '5', '1', 'Y', '2050-12-31', '2024-02-24 10:34:15'),
(9, 'bonus10', '500', '3000', '10', '10000', 'Y', '2050-12-31', '2024-02-24 10:35:48'),
(10, 'bonus15', '3001', '8000', '15', '10000', 'Y', '2050-12-31', '2024-02-24 10:38:42'),
(11, 'bonus18', '8001', '15000', '18', '10000', 'Y', '2050-12-31', '2024-02-24 10:39:21'),
(12, 'bonus20', '15001', '50000', '20', '10000', 'Y', '2050-12-31', '2024-02-24 10:41:23');

-- --------------------------------------------------------

--
-- Table structure for table `plan`
--

CREATE TABLE `plan` (
  `id` int(11) NOT NULL,
  `name` varchar(200) NOT NULL,
  `price` varchar(100) NOT NULL,
  `total_video` varchar(100) NOT NULL,
  `total_comment` varchar(100) NOT NULL,
  `total_like` varchar(100) NOT NULL,
  `total_video_price` varchar(100) NOT NULL,
  `total_video_comment` varchar(100) NOT NULL,
  `total_video_like` varchar(100) NOT NULL,
  `earn_upto` varchar(50) NOT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `plan`
--

INSERT INTO `plan` (`id`, `name`, `price`, `total_video`, `total_comment`, `total_like`, `total_video_price`, `total_video_comment`, `total_video_like`, `earn_upto`, `date`) VALUES
(1, 'Free', '0', '3', '4', '5', '5', '3', '2', '300', '2024-04-02 06:45:47'),
(2, 'Basic', '100', '6', '8', '10', '10', '6', '4', '600', '2024-04-02 06:45:47'),
(3, 'Silver', '200', '12', '16', '20', '20', '12', '8', '1200', '2024-04-02 06:46:22'),
(4, 'Gold', '500', '30', '40', '50', '50', '30', '20', '3000', '2024-04-02 06:46:22');

-- --------------------------------------------------------

--
-- Table structure for table `platforms`
--

CREATE TABLE `platforms` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `status` varchar(1) NOT NULL DEFAULT 'Y',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `platforms`
--

INSERT INTO `platforms` (`id`, `name`, `status`, `date`) VALUES
(1, 'Instagram', 'Y', '2024-04-08 11:41:32'),
(2, 'Facebook', 'Y', '2024-04-08 12:06:41'),
(3, 'Twitter', 'Y', '2024-04-08 12:06:49'),
(4, 'Linkdin', 'Y', '2024-04-08 12:06:59');

-- --------------------------------------------------------

--
-- Table structure for table `reffer_bonus`
--

CREATE TABLE `reffer_bonus` (
  `id` int(11) NOT NULL,
  `referral` varchar(100) NOT NULL,
  `applier` varchar(100) NOT NULL,
  `status` varchar(1) NOT NULL DEFAULT 'N',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `reffer_bonus`
--

INSERT INTO `reffer_bonus` (`id`, `referral`, `applier`, `status`, `date`) VALUES
(1, '250', '200', 'N', '2023-09-30 08:52:42'),
(5, '250', '20', 'Y', '2023-12-14 10:06:06');

-- --------------------------------------------------------

--
-- Table structure for table `role`
--

CREATE TABLE `role` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `display_name` varchar(100) NOT NULL,
  `view` varchar(100) NOT NULL,
  `delete_d` varchar(100) NOT NULL,
  `update_d` varchar(100) NOT NULL,
  `role_assign` varchar(1) NOT NULL DEFAULT 'N',
  `status` varchar(1) NOT NULL DEFAULT 'N',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `role`
--

INSERT INTO `role` (`id`, `name`, `display_name`, `view`, `delete_d`, `update_d`, `role_assign`, `status`, `date`) VALUES
(3, 'Super Admin', 'Super Administration', 'true', 'true', 'true', 'Y', 'N', '2022-07-23 00:43:22'),
(5, 'Developer', 'For developer', 'true', 'true', 'true', 'Y', 'N', '2023-02-17 06:14:26'),
(6, 'View Admin', 'View Only', 'true', 'false', 'false', 'Y', 'N', '2023-03-01 10:36:21');

-- --------------------------------------------------------

--
-- Table structure for table `role_assign`
--

CREATE TABLE `role_assign` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `role_id` int(11) NOT NULL,
  `status` varchar(1) NOT NULL DEFAULT 'Y',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `role_assign`
--

INSERT INTO `role_assign` (`id`, `user_id`, `role_id`, `status`, `date`) VALUES
(4, 14, 3, 'Y', '2023-02-16 09:07:07'),
(5, 15, 5, 'Y', '2023-03-03 06:05:15'),
(6, 16, 5, 'Y', '2024-04-16 07:37:27');

-- --------------------------------------------------------

--
-- Table structure for table `statement`
--

CREATE TABLE `statement` (
  `id` int(11) NOT NULL,
  `mobile` varchar(50) DEFAULT NULL,
  `type` varchar(50) DEFAULT NULL,
  `amount` varchar(50) DEFAULT NULL,
  `total_balance` varchar(50) DEFAULT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'Y',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tasks_with_name`
--

CREATE TABLE `tasks_with_name` (
  `id` int(11) NOT NULL,
  `task_url` varchar(200) NOT NULL,
  `type` varchar(100) NOT NULL,
  `platform_id` int(11) NOT NULL,
  `comment_details` varchar(200) DEFAULT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tasks_with_name`
--

INSERT INTO `tasks_with_name` (`id`, `task_url`, `type`, `platform_id`, `comment_details`, `date`) VALUES
(1, 'https://www.instagram.com/p/Cx0h2Zzx_6l/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'LIKE', 1, '', '2024-04-28 18:30:00'),
(2, 'https://fb.watch/rmfAgR-0sI/', 'COMMENT', 2, 'Hello, Buddy', '2024-04-26 18:30:00'),
(3, 'https://www.instagram.com/p/CqLrMMFytHe/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'LIKE', 1, '', '2024-04-27 06:51:13'),
(4, 'https://www.instagram.com/p/CqLrMMFytHe/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, NULL, '2024-04-10 11:25:45'),
(5, 'https://www.instagram.com/reel/C5inGM1vPj0/?utm_source=ig_web_copy_link', 'LIKE', 1, NULL, '2024-04-10 11:26:24'),
(6, 'https://www.instagram.com/reel/C5inGM1vPj0/?utm_source=ig_web_copy_link', 'COMMENT', 1, '', '2024-04-27 06:51:36'),
(7, 'https://www.instagram.com/reel/C5gCOKyPTRC/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'LIKE', 1, '', '2024-04-27 18:30:00'),
(8, 'https://www.instagram.com/reel/C5gCOKyPTRC/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, NULL, '2024-04-10 11:27:09'),
(9, 'https://www.instagram.com/reel/C5a5gQ8xbQb/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'LIKE', 1, NULL, '2024-04-26 11:27:43'),
(10, 'https://www.instagram.com/reel/C5a5gQ8xbQb/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, NULL, '2024-04-10 11:27:57'),
(11, 'https://www.instagram.com/reel/C5TKTMmxWK8/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'LIKE', 1, '', '2024-04-28 18:30:00'),
(12, 'https://www.instagram.com/reel/C5TKTMmxWK8/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, NULL, '2024-04-10 11:28:40'),
(13, 'https://www.instagram.com/reel/C5OABgCx_ld/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'LIKE', 1, NULL, '2024-04-10 11:28:59'),
(14, 'https://www.instagram.com/reel/C5OABgCx_ld/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, NULL, '2024-04-10 11:29:09'),
(15, 'https://www.instagram.com/p/Cx0h2Zzx_6l/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, 'Hello, testing Person', '2024-04-11 06:57:31'),
(16, 'https://www.instagram.com/p/Cx0h2Zzx_6l/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'LIKE', 2, '', '2024-04-28 18:30:00'),
(25, 'https://www.instagram.com/p/Cx0h2Zzx_6l/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, 'The colors in this picture are so vibrant and alive. It\'s like a burst of joy', '2024-04-11 07:17:06'),
(26, 'https://www.instagram.com/p/Cx0h2Zzx_6l/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 2, NULL, '2024-04-11 07:17:32'),
(27, 'image/video/video-1712820427897-429632752.mp4', 'VIDEO', 1, NULL, '2024-04-11 07:27:07'),
(28, 'image/video/video-1712820584291-173642796.mp4', 'VIDEO', 1, '', '2024-04-26 18:30:00'),
(29, 'image/video/video-1712820631986-473334909.mp4', 'VIDEO', 4, NULL, '2024-04-11 07:30:31'),
(31, 'https://www.instagram.com/p/Cx0h2Zzx_6l/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, 'The colors in this picture are so vibrant and alive. It\'s like a burst of joy', '2024-04-11 07:55:44'),
(32, 'https://www.instagram.com/p/Cx0h2Zzx_6l/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, 'Hello, Testing Gays', '2024-04-11 07:56:17'),
(33, 'https://www.instagram.com/p/Cx0h2Zzx_6l/?utm_source=ig_web_copy_link&igsh=MzRlODBiNWFlZA==', 'COMMENT', 1, 'Hello, Testing Gays', '2024-04-13 10:09:02');

-- --------------------------------------------------------

--
-- Table structure for table `user_details`
--

CREATE TABLE `user_details` (
  `id` int(11) NOT NULL,
  `username` varchar(200) NOT NULL,
  `mobile` varchar(200) NOT NULL,
  `password` varchar(200) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `pincode` varchar(100) DEFAULT NULL,
  `uid` varchar(50) NOT NULL,
  `is_active` varchar(1) NOT NULL DEFAULT 'N',
  `reffer_by` varchar(200) DEFAULT NULL,
  `reffer_code` varchar(200) DEFAULT NULL,
  `plan_type` int(11) DEFAULT 1,
  `upi_id` varchar(100) DEFAULT NULL,
  `bank_name` varchar(100) DEFAULT NULL,
  `ifsc_code` varchar(100) DEFAULT NULL,
  `ac_no` varchar(100) DEFAULT NULL,
  `ac_name` varchar(100) DEFAULT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp(),
  `purchase_date` datetime NOT NULL DEFAULT current_timestamp(),
  `plan_expire` timestamp NOT NULL DEFAULT current_timestamp(),
  `status` varchar(1) DEFAULT 'Y'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user_details`
--

INSERT INTO `user_details` (`id`, `username`, `mobile`, `password`, `email`, `pincode`, `uid`, `is_active`, `reffer_by`, `reffer_code`, `plan_type`, `upi_id`, `bank_name`, `ifsc_code`, `ac_no`, `ac_name`, `date`, `purchase_date`, `plan_expire`, `status`) VALUES
(96, 'Tarun', '8690708302', '$2b$12$mVkfHwCkF1wiGUuL6v/nqOKi4JrMC6dLMXMXS8qxhMDslh9Ai6Hxe', 'tsoni9742@gmail.com', NULL, '100002', 'Y', 'GJpQpVEO', '5Zw8gbwv', 1, NULL, NULL, NULL, NULL, NULL, '2024-05-02 12:47:00', '2024-05-02 18:17:00', '2024-05-02 12:47:00', 'Y');

-- --------------------------------------------------------

--
-- Table structure for table `user_level`
--

CREATE TABLE `user_level` (
  `id` int(11) NOT NULL,
  `user_reffral` varchar(100) DEFAULT NULL,
  `level_1` varchar(100) DEFAULT NULL,
  `level_2` varchar(100) DEFAULT NULL,
  `level_3` varchar(100) DEFAULT NULL,
  `level_4` varchar(100) DEFAULT NULL,
  `level_5` varchar(100) DEFAULT NULL,
  `level_6` varchar(100) DEFAULT NULL,
  `level_7` varchar(100) DEFAULT NULL,
  `level_8` varchar(100) DEFAULT NULL,
  `level_9` varchar(100) DEFAULT NULL,
  `status1` varchar(100) NOT NULL DEFAULT 'Pending',
  `status2` varchar(100) NOT NULL DEFAULT 'Pending',
  `status3` varchar(100) NOT NULL DEFAULT 'Pending',
  `status4` varchar(100) NOT NULL DEFAULT 'Pending',
  `status5` varchar(100) NOT NULL DEFAULT 'Pending',
  `status6` varchar(100) NOT NULL DEFAULT 'Pending',
  `status7` varchar(100) NOT NULL DEFAULT 'Pending',
  `status8` varchar(100) NOT NULL DEFAULT 'Pending',
  `status9` varchar(100) NOT NULL DEFAULT 'Pending',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user_level`
--

INSERT INTO `user_level` (`id`, `user_reffral`, `level_1`, `level_2`, `level_3`, `level_4`, `level_5`, `level_6`, `level_7`, `level_8`, `level_9`, `status1`, `status2`, `status3`, `status4`, `status5`, `status6`, `status7`, `status8`, `status9`, `date`) VALUES
(14, 'GJpQpVEO', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', 'Pending', 'Pending', 'Pending', 'Pending', 'Pending', 'Pending', 'Pending', 'Pending', '2024-04-08 06:29:59');

-- --------------------------------------------------------

--
-- Table structure for table `wallet`
--

CREATE TABLE `wallet` (
  `id` int(11) NOT NULL,
  `user_name` varchar(200) NOT NULL,
  `wallet_balance` varchar(200) NOT NULL,
  `winning_wallet` varchar(100) NOT NULL DEFAULT '0',
  `status` varchar(1) NOT NULL DEFAULT 'Y',
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `wallet`
--

INSERT INTO `wallet` (`id`, `user_name`, `wallet_balance`, `winning_wallet`, `status`, `date`) VALUES
(46, '8898765437', '1800', '60', 'Y', '2024-04-05 05:43:24'),
(88, '8690708302', '0', '0', 'Y', '2024-05-02 12:47:00'),
(89, '9794368090', '600', '50', 'Y', '2024-05-02 12:47:36'),
(90, '8690708301', '900', '0', 'Y', '2024-05-02 12:48:13'),
(91, '9794368091', '1800', '40', 'Y', '2024-05-02 12:49:00'),
(92, '9794368092', '1800', '20', 'Y', '2024-05-03 05:02:13'),
(93, '9794368093', '1000', '0', 'Y', '2024-05-03 07:01:49'),
(94, '9794368094', '900', '0', 'Y', '2024-05-03 07:17:56');

-- --------------------------------------------------------

--
-- Table structure for table `withdrawal`
--

CREATE TABLE `withdrawal` (
  `id` int(11) NOT NULL,
  `user_name` varchar(200) NOT NULL,
  `balance` varchar(200) NOT NULL,
  `Approved_declined_By` varchar(50) NOT NULL DEFAULT 'Not Approved',
  `status` varchar(50) NOT NULL DEFAULT 'Pending',
  `paymethod_id` int(11) NOT NULL,
  `paytype` varchar(50) NOT NULL,
  `reason` varchar(200) DEFAULT NULL,
  `date` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `agents_statement`
--
ALTER TABLE `agents_statement`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `assign_module`
--
ALTER TABLE `assign_module`
  ADD PRIMARY KEY (`id`),
  ADD KEY `module` (`module`),
  ADD KEY `role_x` (`role`);

--
-- Indexes for table `assign_task`
--
ALTER TABLE `assign_task`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `bank_details`
--
ALTER TABLE `bank_details`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `account_number` (`account_number`);

--
-- Indexes for table `buy_plan`
--
ALTER TABLE `buy_plan`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `commets`
--
ALTER TABLE `commets`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `contact`
--
ALTER TABLE `contact`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `deposit`
--
ALTER TABLE `deposit`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `level`
--
ALTER TABLE `level`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `login`
--
ALTER TABLE `login`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `user` (`username`);

--
-- Indexes for table `module`
--
ALTER TABLE `module`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `module_name` (`module_name`);

--
-- Indexes for table `new_payment_details`
--
ALTER TABLE `new_payment_details`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `number` (`number`),
  ADD UNIQUE KEY `upi_id` (`upi_id`);

--
-- Indexes for table `otp`
--
ALTER TABLE `otp`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `number` (`number`);

--
-- Indexes for table `payment_bonus`
--
ALTER TABLE `payment_bonus`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `offer_name` (`offer_name`);

--
-- Indexes for table `plan`
--
ALTER TABLE `plan`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `platforms`
--
ALTER TABLE `platforms`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `reffer_bonus`
--
ALTER TABLE `reffer_bonus`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `role`
--
ALTER TABLE `role`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `display_name` (`display_name`);

--
-- Indexes for table `role_assign`
--
ALTER TABLE `role_assign`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `role` (`role_id`);

--
-- Indexes for table `statement`
--
ALTER TABLE `statement`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `tasks_with_name`
--
ALTER TABLE `tasks_with_name`
  ADD PRIMARY KEY (`id`),
  ADD KEY `platform_id` (`platform_id`);

--
-- Indexes for table `user_details`
--
ALTER TABLE `user_details`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uid` (`uid`),
  ADD UNIQUE KEY `mobile` (`mobile`),
  ADD UNIQUE KEY `reffer_code` (`reffer_code`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indexes for table `user_level`
--
ALTER TABLE `user_level`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `wallet`
--
ALTER TABLE `wallet`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `user_name` (`user_name`);

--
-- Indexes for table `withdrawal`
--
ALTER TABLE `withdrawal`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `agents_statement`
--
ALTER TABLE `agents_statement`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=57;

--
-- AUTO_INCREMENT for table `assign_module`
--
ALTER TABLE `assign_module`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=484;

--
-- AUTO_INCREMENT for table `assign_task`
--
ALTER TABLE `assign_task`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=45;

--
-- AUTO_INCREMENT for table `bank_details`
--
ALTER TABLE `bank_details`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `buy_plan`
--
ALTER TABLE `buy_plan`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=116;

--
-- AUTO_INCREMENT for table `commets`
--
ALTER TABLE `commets`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `contact`
--
ALTER TABLE `contact`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `deposit`
--
ALTER TABLE `deposit`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=281;

--
-- AUTO_INCREMENT for table `level`
--
ALTER TABLE `level`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `login`
--
ALTER TABLE `login`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT for table `module`
--
ALTER TABLE `module`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=39;

--
-- AUTO_INCREMENT for table `new_payment_details`
--
ALTER TABLE `new_payment_details`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `otp`
--
ALTER TABLE `otp`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=28;

--
-- AUTO_INCREMENT for table `payment_bonus`
--
ALTER TABLE `payment_bonus`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT for table `plan`
--
ALTER TABLE `plan`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `platforms`
--
ALTER TABLE `platforms`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `reffer_bonus`
--
ALTER TABLE `reffer_bonus`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `role`
--
ALTER TABLE `role`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `role_assign`
--
ALTER TABLE `role_assign`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `statement`
--
ALTER TABLE `statement`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1302;

--
-- AUTO_INCREMENT for table `tasks_with_name`
--
ALTER TABLE `tasks_with_name`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=35;

--
-- AUTO_INCREMENT for table `user_details`
--
ALTER TABLE `user_details`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=103;

--
-- AUTO_INCREMENT for table `user_level`
--
ALTER TABLE `user_level`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=53;

--
-- AUTO_INCREMENT for table `wallet`
--
ALTER TABLE `wallet`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=95;

--
-- AUTO_INCREMENT for table `withdrawal`
--
ALTER TABLE `withdrawal`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `assign_module`
--
ALTER TABLE `assign_module`
  ADD CONSTRAINT `module` FOREIGN KEY (`module`) REFERENCES `module` (`id`),
  ADD CONSTRAINT `role_x` FOREIGN KEY (`role`) REFERENCES `role` (`id`);

--
-- Constraints for table `role_assign`
--
ALTER TABLE `role_assign`
  ADD CONSTRAINT `role` FOREIGN KEY (`role_id`) REFERENCES `role` (`id`),
  ADD CONSTRAINT `user_id` FOREIGN KEY (`user_id`) REFERENCES `login` (`id`);

--
-- Constraints for table `tasks_with_name`
--
ALTER TABLE `tasks_with_name`
  ADD CONSTRAINT `platform_id` FOREIGN KEY (`platform_id`) REFERENCES `platforms` (`id`);

DELIMITER $$
--
-- Events
--
CREATE DEFINER=`root`@`localhost` EVENT `otp_delete` ON SCHEDULE EVERY 1 SECOND STARTS '2024-04-30 12:21:45' ENDS '2034-04-30 12:21:45' ON COMPLETION NOT PRESERVE ENABLE DO delete from `otp` where DATE_ADD(`date`, INTERVAL 10 MINUTE) < CURRENT_TIMESTAMP()$$

CREATE DEFINER=`root`@`localhost` EVENT `buy_plan` ON SCHEDULE EVERY 1 SECOND STARTS '2024-04-30 12:26:26' ENDS '2034-04-30 12:26:26' ON COMPLETION NOT PRESERVE ENABLE DO UPDATE `buy_plan` SET `status`='Expired' WHERE date(`expire_date`) < CURRENT_TIMESTAMP()$$

DELIMITER ;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
