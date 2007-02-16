/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * A slightly safer version of mkstemp(3)
 *
 * In this version, the file is initially created mode 0, (using umask) and
 * then chmod-ed to the requested permissions after calling mkstemp(3).
 * This guarantees that the file is not even momentarily open beyond the
 * requested permissions.
 *
 * Return values:
 *
 * Like mkstemp, it returns the file descriptor of the open file, or -1
 * on error.
 *
 * In addition to the errno values documented for mkstemp(3), this functio
 * can also fail with any of the errno values documented for chmod(2).
 *
 */
int mkstemp_mode(char* template, mode_t requested_filemode);
