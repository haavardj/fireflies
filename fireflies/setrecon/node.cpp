//====================================================================
// Filename:      node.cpp
// Description:   
//
// Initial implementation by: Sachin Agarwal, ska@bu.edu
//               modified by: Ari Trachtenberg, trachten@bu.edu
//                   Version: 0.998 Beta
//                      Date: 06/23/2004
// Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
// Modified at:   Mon Jan 16 18:44:32 2006
// Licence: GPL (see LICENSE file).
//  
//                
// $Id: node.cpp,v 1.1.1.1 2006/01/20 12:41:27 haavardj Exp $
//                
//====================================================================


#include "node.h"
#include "reconciled_set.h"

/*
node::node(reconciled_set *set)
{
  refc = 0;
  base = set;
  intree = false;
  setsize = 0;
  

  child = new node*[base->p];
  for(long i=0; i< base->p; i++)
    child[i]=NULL;
}
*/




node *node::delete_from_tree(ZZ_p element_to_delete)
{
  node *retnode = this;
  assert(refc > 0);
  assert(setsize > 0);
  //assert(setsize == terminal_data().length());
  setsize -= 1;


  if (node_type == NODE_TYPE_NON_TERMINAL){
    
    assert(hash_vector.length() == base->mbar);

    if(setsize > base->mbar) {

      //Dont need to convert to a terminal node.
      for(int ii=0; ii < base->mbar; ii++){
	hash_vector[ii] /= (base->samples[ii]-element_to_delete);
      }
      for(int ii=0; ii< valids.length(); ii++){
	extra_hashes[ii] /= (valids[ii]-element_to_delete);
      }

      long position = base->position_of_child(element_to_delete, start, stop);
      child[position] = child[position]->delete_from_tree(element_to_delete);      
    }
    else{
      
      //Need to convert to a terminal node
      vec_ZZ_p allelements = terminal_data();
      vec_ZZ_p newset;
      long alllength = allelements.length();
      newset.SetLength(alllength-1);      

      long ctr = 0;
      for(int ii = 0 ;ii < alllength; ii++) {

	//Weeding out the element to be deleted
	if (allelements[ii] != element_to_delete)
	  newset[ctr++] = allelements[ii];
      }
      
      assert(alllength == (newset.length() + 1));		  
      ZZ start = start;
      ZZ stop = stop;
      intree = false;
      unref();

      retnode = base->recurse_make(newset, start, stop);
      retnode->ref();
      retnode->intree = true;
      assert(retnode->node_type == NODE_TYPE_TERMINAL);
    }
  }
  else {

    assert(hash_vector.length() <=  base->mbar);
    
    if(setsize==0){

      /* The node needs to be deleted since this one element is
	 the element to be deleted. */
      //deletetree(root);
      intree = false;
      unref();
      
      retnode = base->recurse_make(vec_ZZ_p(),  ZZ_zero, base->max);
      retnode->ref();
      retnode->intree = true;
    }
    else{

      assert(setsize == hash_vector.length()-1);
      long l = hash_vector.length();
      vec_ZZ_p tempset;
      tempset.SetLength(l-1);
      long ctr=0;

      
      //Weeding out the element to be deleted.      
      for(int ii = 0 ; ii < l; ii++){
	
	if (hash_vector[ii]!=element_to_delete){	      
	  tempset[ctr++] = hash_vector[ii];  
	  assert(ctr <= (l-1));
	}
      }
      assert(ctr == (l-1));
      hash_vector = tempset;
    }
  }
  return retnode;
}



node::node(reconciled_set *set, vec_ZZ_p& subset_pp, ZZ strt, ZZ stp)
/* Constructor for node
   R: Subset in vector space whose hashes have to be stored, samples, number of subpartitions
   E: Creates node
   M: valids - makes it contain the validation points for this node
	*/
{
  start = strt;
  stop = stp;
  refc = 0;
  setsize=subset_pp.length();
  base = set;
  intree = false;
  
  child = new node*[base->p];
  for(long i=0; i< base->p; i++)
    child[i]=NULL;
  

  assert(base->mbar == base->samples.length());
  if(setsize <= base->mbar)
    {
      node_type = NODE_TYPE_TERMINAL;
      hash_vector=subset_pp;
      assert(hash_vector.length() <= base->samples.length());
      extra_hashes = vec_ZZ_p();
      valids = vec_ZZ_p();      
    }
  else
    {
      node_type = NODE_TYPE_NON_TERMINAL;
      hash_vector=calc_poly(subset_pp, base->samples);
      valids = compute_validationpoints(base->mbar,
					base->k,
					power(ZZ_two,base->bitsize)+base->mbar/2 + 2,
					ZZ_p::modulus() - (base->mbar/2) + 1,
					start); // start item serves as a seed for the random numbers      
      extra_hashes = calc_poly(subset_pp, valids); //Extra sample points evaluation for probabilistic

      assert(hash_vector.length() == base->samples.length());
    }   
}


node::~node(){ 
  assert(refc == 0);
  assert(intree == false);

  valids.kill(); 
  hash_vector.kill(); 
  extra_hashes.kill();

  for (int i = 0; i < base->p; i++){
    if (child[i] != NULL){
      child[i]->intree = false;
      child[i]->unref();
      child[i] = NULL;
    }
  }
}





node *node::getChild(int nr)
{
  assert(refc > 0);
  assert(base->p >= nr);
  return child[nr];
}

bool node::isTerminal()
{
  assert(refc > 0);
  return node_type == NODE_TYPE_TERMINAL;
}

void node::printNode(int level)
{
  assert(refc > 0);
  std::cout << "\nlevel:" << level;
  std::cout << "\nNode type:" <<node_type;
  std::cout << "\nhsh_vector len:" <<hash_vector.length();
  std::cout << ", Node setsize:"<<setsize << "\n";
  std::cout << "hash_vector: " <<hash_vector <<"\n";
  std::cout << "start: " <<start <<"\n";
  std::cout << "stop: " <<stop <<"\n";
  std::cout << "intree: " << intree << "\n";
  std::cout << "refc: " << refc << "\n";
  for(int i = 0; i< base->p; i++)
    {
      if (child[i] != NULL)
	child[i]->printNode(level + 1);
    }
}



/*
 * Returns data stored in the subtree (terminal data).
 */
vec_ZZ_p node::terminal_data()
{
  assert(refc > 0);
  vec_ZZ_p tempreturn;
  
  if(node_type == NODE_TYPE_TERMINAL) //Terminal node
    {
      assert(hash_vector.length() == setsize);
      tempreturn = hash_vector;
    }
  else
    {
      assert(child != NULL);
      for(int ii=0; ii< base->p; ii++)
	{
	  if (child[ii] == NULL)
	    continue;

	  vec_ZZ_p t;
	  int x;
	  int y;
	  x = tempreturn.length();

	  t = child[ii]->terminal_data();

	  y = t.length();

	  assert(t.length() == child[ii]->setsize);
	  append(tempreturn, t);

	  assert(tempreturn.length() == (x+y));
	}
    }
  if (tempreturn.length() != setsize){

    std::cout << "terminal data length=" << tempreturn.length()
	      << " setsize=" << setsize << "\n"
	      << " set=" << tempreturn << "\n";
    //for (int i=0; i <tempretur
  }
  assert(tempreturn.length() == setsize);
  return tempreturn;
}
