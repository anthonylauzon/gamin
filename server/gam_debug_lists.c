/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/. 
 */

#include "config.h"
#include <string.h> /* for memset() debug */
#include "glib.h"

GList*
g_list_alloc (void)
{
  GList *list;
  
  list = g_new0 (GList, 1);
  
  return list;
}

void
g_list_free (GList *list)
{
  GList *last;
  
  while (list)
    {
      last = list;
      list = list->next;
      memset(last, -1 , sizeof(GList));
      g_free (last);
    }
}

void
g_list_free_1 (GList *list)
{
  memset(list, -1 , sizeof(GList)); /* segfault with NULL on purpose */
  g_free (list);
}

GList*
g_list_append (GList	*list,
	       gpointer	 data)
{
  GList *new_list;
  GList *last;
  
  new_list = g_list_alloc ();
  new_list->data = data;
  
  if (list)
    {
      last = g_list_last (list);
      /* g_assert (last != NULL); */
      last->next = new_list;
      new_list->prev = last;

      return list;
    }
  else
    return new_list;
}

GList*
g_list_prepend (GList	 *list,
		gpointer  data)
{
  GList *new_list;
  
  new_list = g_list_alloc ();
  new_list->data = data;
  
  if (list)
    {
      if (list->prev)
	{
	  list->prev->next = new_list;
	  new_list->prev = list->prev;
	}
      list->prev = new_list;
      new_list->next = list;
    }
  
  return new_list;
}

GList*
g_list_remove_all (GList	*list,
		   gconstpointer data)
{
  GList *tmp = list;

  while (tmp)
    {
      if (tmp->data != data)
	tmp = tmp->next;
      else
	{
	  GList *next = tmp->next;

	  if (tmp->prev)
	    tmp->prev->next = next;
	  else
	    list = next;
	  if (next)
	    next->prev = tmp->prev;

	  g_list_free_1 (tmp);
	  tmp = next;
	}
    }
  return list;
}

static inline GList*
_g_list_remove_link (GList *list,
		     GList *link)
{
  if (link)
    {
      if (link->prev)
	link->prev->next = link->next;
      if (link->next)
	link->next->prev = link->prev;
      
      if (link == list)
	list = list->next;
      
      link->next = NULL;
      link->prev = NULL;
    }
  
  return list;
}

GList*
g_list_delete_link (GList *list,
		    GList *link)
{
  list = _g_list_remove_link (list, link);
  g_list_free_1 (link);

  return list;
}

GList*
g_list_copy (GList *list)
{
  GList *new_list = NULL;

  if (list)
    {
      GList *last;

      new_list = g_list_alloc ();
      new_list->data = list->data;
      last = new_list;
      list = list->next;
      while (list)
	{
	  last->next = g_list_alloc ();
	  last->next->prev = last;
	  last = last->next;
	  last->data = list->data;
	  list = list->next;
	}
    }

  return new_list;
}

gpointer
g_list_nth_data (GList     *list,
		 guint      n)
{
  while ((n-- > 0) && list)
    list = list->next;
  
  return list ? list->data : NULL;
}

GList*
g_list_find (GList         *list,
	     gconstpointer  data)
{
  while (list)
    {
      if (list->data == data)
	break;
      list = list->next;
    }
  
  return list;
}

GList*
g_list_last (GList *list)
{
  if (list)
    {
      while (list->next)
	list = list->next;
    }
  
  return list;
}

GList*
g_list_first (GList *list)
{
  if (list)
    {
      while (list->prev)
	list = list->prev;
    }
  
  return list;
}

guint
g_list_length (GList *list)
{
  guint length;
  
  length = 0;
  while (list)
    {
      length++;
      list = list->next;
    }
  
  return length;
}

