
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
 * Inspired from the work of Francis Giraldeau.
 */
#ifndef SPAN_LATENCY_TRACKER_ABI_H_
#define SPAN_LATENCY_TRACKER_ABI_H_

#define SPAN_LATENCY_TRACKER_PROC "latency-tracker-spans"
#define SPAN_LATENCY_TRACKER_PATH "/proc/" SPAN_LATENCY_TRACKER_PROC

#define SPAN_LATENCY_TRACKER_PROC_CTL "mod_ctl"
#define SPAN_LATENCY_TRACKER_PROC_FILTER "filter"

#define COOKIE_MAX_SIZE 64
#define SPAN_ID_MAX_SIZE 16
#define TRACE_ID_MAX_SIZE 32
#define SERVICE_NAME_MAX_SIZE 12
#define SYSCALL_NAME_MAX_SIZE 16

#define DEBUGFS_DIR_PATH "channels"


enum span_latency_module_cmd {
	SPAN_LATENCY_TRACKER_MODULE_REGISTER = 0,
	SPAN_LATENCY_TRACKER_MODULE_UNREGISTER = 1,
	SPAN_LATENCY_TRACKER_MODULE_STACK = 2,
};

/*
 * Structure to send messages to the kernel module.
 */
struct span_latency_tracker_module_msg {
	int cmd;                 /* Command */
	char service_name[SERVICE_NAME_MAX_SIZE]; /* Service name*/
} __attribute__((packed));

/*
 * Borrow some unused range of LTTng ioctl.
 */
#define SPAN_LATENCY_TRACKER_IOCTL  _IO(0xF6, 0x91)

#endif  /* SPAN_LATENCY_TRACKER_ABI_H_  */
