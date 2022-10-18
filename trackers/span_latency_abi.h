
/*
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Inspired from https://github.com/giraldeau/perfuser, by Francis Giraldeau.
 */
#ifndef SPAN_LATENCY_TRACKER_ABI_H_
#define SPAN_LATENCY_TRACKER_ABI_H_

#define USERSPACE_TRACKER_PROC "userspace"
#define USERSPACE_TRACKER_PATH "/proc/" USERSPACE_TRACKER_PROC

#define SERVICE_NAME_MAX_SIZE 28
#define SPAN_ID_MAX_SIZE 32
#define SYSCALL_NAME_MAX_SIZE 14

#define DEBUGFS_DIR_PATH "channels"


enum userspace_module_cmd {
  USERSPACE_TRACKER_MODULE_REGISTER = 0,
  USERSPACE_TRACKER_MODULE_UNREGISTER = 1,
  USERSPACE_TRACKER_MODULE_STACK = 2,
};

/*
 * Structure to send messages to the kernel module.
 */
struct userspace_tracker_module_msg {
	int cmd;                 /* Command */
	char service_name[SERVICE_NAME_MAX_SIZE]; /* Service name*/
} __attribute__((packed));

/*
 * Borrow some unused range of LTTng ioctl.
 */
#define USERSPACE_TRACKER_IOCTL  _IO(0xF6, 0x91)

#endif  /* SPAN_LATENCY_TRACKER_ABI_H_  */
